# Bootstrap contracts: init is idempotent; seal refuses to run half-way when
# the signer identity is not registered yet.
use std/assert
use std/testing *

use ../nu-cybergraph/init.nu
use ../nu-cybergraph/seal.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/verify.nu
use ../nu-cybergraph/_record.nu [link-bytes]
use ../nu-cybergraph/_fs.nu [copy-file copy-tree]
use ../nu-cybergraph/_deps/pubkey.nu [pubkey]

const P1 = "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
const P2 = "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
const P3 = "QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV"

# Overwrite a link file with a DIFFERENT valid record, keeping the old name —
# the tamper that self-addressing exists to catch: canonical, parseable, and
# lying about which act it is.
def swap-record [file: path rec: record] {
    link-bytes $rec | save --force --raw $file
}

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

def make-bare-repo [tmp_dir: path]: nothing -> record {
    let repo = $tmp_dir | path join repo
    mkdir $repo
    ^git init --object-format=sha256 -q $repo
    ^git -C $repo config user.name t
    ^git -C $repo config user.email t@t
    let key = $tmp_dir | path join key
    ^ssh-keygen -t ed25519 -f $key -N "" -q
    ^git -C $repo config user.signingKey $key
    {repo: $repo key: $key}
}

@test
def "init is idempotent: re-run reports, never duplicates" [] {
    let r = make-bare-repo $in.tmp_dir
    init --repo $r.repo
    init --repo $r.repo
    assert equal (glob ($r.repo | path join cybergraph multiproofs pubkeys *.pub) | length) 1
    assert (($r.repo | path join cybergraph links) | path exists)
    assert (($r.repo | path join cybergraph certs) | path exists)
}

# `init` says its job is to establish the signer identity, so a run that
# establishes none has not done it. It used to print `cybergraph layout ready`
# over an empty trust list and exit clean; the first `link add` then said
# `run nu-cybergraph init first`, naming the command that had just succeeded.
@test
def "init refuses when it registered no signer" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $tmp_dir | path join keyless
    mkdir $repo
    ^git init --object-format=sha256 -q $repo
    ^git -C $repo config user.name t
    ^git -C $repo config user.email t@t

    let err = try { init --repo $repo; null } catch {|e| $e.msg }
    assert ($err != null) "init reported success with an empty pubkeys/"
    # Both routes out are named, because the operator has heard of neither.
    assert ($err | str contains "user.signingKey")
    assert ($err | str contains "--pubkey")
    # And it refuses before claiming a layout: no links/ to suggest otherwise.
    assert not (($repo | path join cybergraph links) | path exists)
}

# The other half of the same rule: a key passed explicitly is a registration,
# so the refusal above must not fire on a repo whose git config names nothing.
@test
def "init with an explicit pubkey needs no git signing key" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $tmp_dir | path join explicit
    mkdir $repo
    ^git init --object-format=sha256 -q $repo
    ^git -C $repo config user.name t
    ^git -C $repo config user.email t@t
    let key = $tmp_dir | path join explicit-key
    ^ssh-keygen -t ed25519 -f $key -N "" -q

    init --repo $repo --pubkey $"($key).pub"
    assert (($repo | path join cybergraph links) | path exists)
    let registered = ls ($repo | path join cybergraph multiproofs pubkeys) | get name
    assert equal ($registered | length) 1
    # The key that landed is the key named, not merely some key: counting one
    # file would pass on a registration that ignored --pubkey entirely.
    assert equal (
        open --raw ($registered | first) | str trim
    ) (
        open --raw $"($key).pub" | pubkey canonical | str trim
    ) "the registered key is not the one --pubkey named"
}

@test
def "seal before init fails fast, before anything is written" [] {
    let r = make-bare-repo $in.tmp_dir
    "hi\n" | save ($r.repo | path join readme.md)
    ^git -C $r.repo add -A

    let err = try { seal --repo $r.repo --no-stamp; null } catch {|e| $e.msg }
    assert ($err != null) "seal ran without a registered pubkey"
    assert ($err | str contains "nu-cybergraph init")
    # Nothing mutated: no manifest, no root statement
    assert not (($r.repo | path join cybergraph multiproofs tree-hashes.csv) | path exists)
}

@test
def "nested graph home: init puts everything under cybergraph/ by default" [] {
    let r = make-bare-repo $in.tmp_dir
    init --repo $r.repo
    assert (($r.repo | path join cybergraph multiproofs pubkeys) | path exists)
    assert (($r.repo | path join cybergraph links) | path exists)

    # An arbitrary user file at the repo root: tracked by git, untouched by
    # the graph — the seal manifest covers only the cybergraph/ subtree
    "arbitrary user file\n" | save ($r.repo | path join notes.md)
    ^git -C $r.repo add -A

    let born = link add $P1 $P2 --repo $r.repo
    assert ($born.path | str contains $"cybergraph(char path_sep)links")
    let sealed = seal --repo $r.repo --no-stamp
    assert equal $sealed.newborn 1
    assert (($r.repo | path join cybergraph certs $"($born.cid).cert.json") | path exists)
    let manifest = open --raw ($r.repo | path join cybergraph multiproofs tree-hashes.csv)
        | from csv --no-infer
    assert ($manifest | where filepath == "notes.md" | is-empty)
    assert ($manifest | where filepath == $"links/($born.cid).json" | is-not-empty)

    # Discovery is implicit from here on: verify finds the nested home itself
    assert (verify $born.cid --repo $r.repo | first | get valid)
}

@test
def "link add refuses a repeat of the triple — one act, one file" [] {
    let r = make-bare-repo $in.tmp_dir
    init --repo $r.repo
    let born = link add $P1 $P2 --repo $r.repo

    # The record IS the triple, so a repeat is byte-identical: refused by the
    # file's existence, naming the existing CID
    let err = try { link add $P1 $P2 --repo $r.repo; null } catch {|e| $e.msg }
    assert ($err != null) "duplicate triple was recorded"
    assert ($err | str contains $born.cid)
    assert equal (glob ($r.repo | path join cybergraph links *.json) | length) 1
}

@test
def "seal refuses a link file that does not match its content address" [] {
    let r = make-bare-repo $in.tmp_dir
    init --repo $r.repo
    let born = link add $P1 $P2 --repo $r.repo
    swap-record $born.path (open --raw $born.path | from json | update cid_to $P3)

    let err = try { seal --repo $r.repo --no-stamp; null } catch {|e| $e.msg }
    assert ($err != null) "seal signed a record that is not its own address"
    assert ($err | str contains $born.cid) $"error should name the offending file: ($err)"
    # Aborted before multiproof wrote anything — no manifest, no certificate
    assert not (($r.repo | path join cybergraph multiproofs tree-hashes.csv) | path exists)
    assert not (($r.repo | path join cybergraph certs $"($born.cid).cert.json") | path exists)
}

@test
def "a record tampered after its birth seal aborts the next seal too" [] {
    let r = make-bare-repo $in.tmp_dir
    init --repo $r.repo
    let born = link add $P1 $P2 --repo $r.repo
    assert equal (seal --repo $r.repo --no-stamp | get newborn) 1

    # Every seal re-attests the whole catalogue, so the check covers links that
    # already have a certificate — not just the newborns of this seal
    swap-record $born.path (open --raw $born.path | from json | update cid_to $P3)
    let err = try { seal --repo $r.repo --no-stamp; null } catch {|e| $e.msg }
    assert ($err != null) "a tampered record was re-attested by a later seal"
    assert ($err | str contains $born.cid)
}

# The signing identity is the repo's git config, so both key failures below are
# reached by re-pointing user.signingKey after init — there is no --key to pass.
@test
def "seal fails fast when the signing key has no public half beside it" [] {
    let r = make-bare-repo $in.tmp_dir
    init --repo $r.repo
    let other = $in.tmp_dir | path join other-key
    ^ssh-keygen -t ed25519 -f $other -N "" -q
    rm $"($other).pub"
    ^git -C $r.repo config user.signingKey $other

    let err = try { seal --repo $r.repo --no-stamp; null } catch {|e| $e.msg }
    assert ($err != null) "seal ran without the public key present"
    assert ($err | str contains $"($other | path expand).pub")
    assert not (($r.repo | path join cybergraph multiproofs tree-hashes.csv) | path exists)
}

@test
def "seal with an unregistered signing key names the fix" [] {
    let r = make-bare-repo $in.tmp_dir
    init --repo $r.repo
    let other = $in.tmp_dir | path join other-key
    ^ssh-keygen -t ed25519 -f $other -N "" -q
    ^git -C $r.repo config user.signingKey $other

    let err = try { seal --repo $r.repo --no-stamp; null } catch {|e| $e.msg }
    assert ($err != null) "seal accepted a key that is not registered"
    assert ($err | str contains $"init --pubkey ($other | path expand).pub")
    # multiproof's own check fires only after it has rewritten these
    assert not (($r.repo | path join cybergraph multiproofs tree-hashes.csv) | path exists)
    assert not (($r.repo | path join cybergraph multiproofs tree-root.txt) | path exists)
}

# The copy helpers, on hostile input directly. Every other test reaches them
# through a happy-path `bundle`, `seal` or `import`, so a refusal that stopped
# working would leave the suite green — and they exist for nothing BUT the
# refusals. `cp` reports an unreadable source on stderr and exits 0, which is
# the whole reason neither of these is a bare `cp`.
#
# Asserted on `debug`, not `msg`: nushell's own IO error says only "I/O error"
# at the top and carries the kind and the path underneath. That the raise comes
# from nushell rather than from a check here is the point — this pins the
# CONTRACT, so a later rewrite back onto `cp` fails loudly.
@test
def "copy-file refuses a source it could not read" [] {
    let tmp_dir = $in.tmp_dir
    let src = $tmp_dir | path join secret.txt
    "bytes that must not vanish quietly\n" | save --raw $src
    ^chmod 000 $src
    let dst = $tmp_dir | path join landing
    mkdir $dst

    let err = try { copy-file $src $dst; null } catch {|e| $e.debug }
    ^chmod 644 $src
    assert ($err != null) "copy-file accepted a copy that produced no file"
    assert ($err | str contains "secret.txt") $"the refusal does not name the file: ($err)"
    assert ($err | str contains "PermissionDenied") $"the refusal does not say what was wrong: ($err)"
    assert not (($dst | path join secret.txt) | path exists) "a file landed for a source that could not be read"
}

# `cp` overwrote a destination silently; `save` refuses one. Pinned because the
# change is deliberate — a copy landing on an existing file is a question here,
# and clobbering a frozen certificate is a defect this repo already has parked.
@test
def "copy-file refuses to overwrite a file that is already there" [] {
    let tmp_dir = $in.tmp_dir
    let src = $tmp_dir | path join new.txt
    "incoming\n" | save --raw $src
    let dst = $tmp_dir | path join frozen.txt
    "must not be clobbered\n" | save --raw $dst

    let err = try { copy-file $src $dst; null } catch {|e| $e.msg }
    assert ($err != null) "copy-file overwrote an existing file"
    assert equal (open --raw $dst) "must not be clobbered\n"
}

@test
def "copy-tree refuses a destination that already exists" [] {
    let tmp_dir = $in.tmp_dir
    let src = $tmp_dir | path join from
    mkdir $src
    "x\n" | save --raw ($src | path join a.txt)
    # Something valuable already standing where the copy would go. `cp` would
    # nest the copy inside it, and the cleanup on a short copy would then
    # delete a directory this call never created.
    let dst = $tmp_dir | path join precious
    mkdir $dst
    "do not delete me\n" | save --raw ($dst | path join keepme.txt)

    let err = try { copy-tree $src $dst; null } catch {|e| $e.msg }
    assert ($err != null) "copy-tree copied into an existing directory"
    assert ($err | str contains "already exists")
    assert (($dst | path join keepme.txt) | path exists) "the pre-existing directory was destroyed"
}

@test
def "copy-tree refuses a tree holding something that is not a regular file" [] {
    let tmp_dir = $in.tmp_dir
    let src = $tmp_dir | path join withlink
    mkdir $src
    "x\n" | save --raw ($src | path join a.txt)
    # Dangling on purpose: `open --raw` follows a link, so this used to come
    # back as the two words `Not found` with nothing naming the bundle.
    ^ln -s /nonexistent/nowhere ($src | path join dangling)

    let err = try { copy-tree $src ($tmp_dir | path join to); null } catch {|e| $e.msg }
    assert ($err != null) "copy-tree followed a symlink out of the tree"
    assert ($err | str contains "dangling") $"the refusal does not name the link: ($err)"
    assert ($err | str contains "not a regular file") $"the refusal does not say what is wrong: ($err)"
}
