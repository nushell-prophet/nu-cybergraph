# Bootstrap contracts: init is idempotent; seal refuses to run half-way when
# the signer identity is not registered yet.
#
# Every seal here passes --allow-untracked-particles. None of these tests is
# about the store's own commit discipline, and they never commit anything: the
# guard `seal` grew would otherwise refuse them all, for a reason each of them
# has already agreed to ignore. tests/test_uncommitted.nu is where the guard itself
# is under test, both ways.
use std/assert
use std/testing *

use ../nu-cybergraph/init.nu
use ../nu-cybergraph/seal.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/verify.nu
use ../nu-cybergraph/_record.nu [ edge-bytes ]
use ../nu-cybergraph/_fs.nu [ copy-file copy-tree list-files list-dirs move-file ]
use ../nu-cybergraph/_layout.nu [ certs-dir order-path order-cert-path ]
use ../nu-cybergraph/_deps/pubkey.nu [ pubkey ]
use ../nu-cybergraph/_deps/cid-v0.nu [ cid-v0 ]

const P1 = "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
const P2 = "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
const P3 = "QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV"

# Overwrite a link file with a DIFFERENT valid record, keeping the old name —
# the tamper that self-addressing exists to catch: canonical, parseable, and
# lying about which act it is.
def swap-record [file: path rec: record] {
    edge-bytes $rec | save --force --raw $file
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

# Idempotence is about the SAME key. Upstream registration is additive, so
# another key under `user.signingKey` is written beside the first.
# `init` establishes identity, so establishing a second one
# has to fail, and has to put back what it added.
@test
def "init refuses to register a second key and undoes what it added" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let key2 = $in.tmp_dir | path join key2

    ^ssh-keygen -t ed25519 -f $key2 -N "" -q
    ^git -C $r.repo config user.signingKey $key2
    let err = try { init --repo $r.repo; null } catch {|e| $e.msg }

    assert ($err != null) "a re-run under another signing key grew the trust list silently"
    assert equal (glob ($r.repo | path join cybergraph multiproofs pubkeys *.pub) | length) 1
    # The route out is named, because a second key IS legal — just never by
    # accident, which is the whole difference this refusal now draws.
    assert ($err | str contains "--co-signer")
}

# What `--co-signer` is for: a key that signs the same seal root as the identity
# does, so one statement carries more than one signature. It never becomes the
# identity — that is read from the key this checkout signs with — so a plain
# re-run over such a home must pass straight through rather than read two keys
# as the accident above.
@test
def "a co-signer joins the trust list and a later init leaves it alone" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let co = $in.tmp_dir | path join extra

    ^ssh-keygen -t ed25519 -f $co -N "" -q
    init --repo $r.repo --co-signer $"($co).pub"
    let pubs = $r.repo | path join cybergraph multiproofs pubkeys

    assert equal (glob ($pubs | path join *.pub) | length) 2

    init --repo $r.repo
    assert equal (glob ($pubs | path join *.pub) | length) 2
    # And it is idempotent for the same reason `init` is: registration compares
    # key material, so the same co-signer twice is one file.
    init --repo $r.repo --co-signer $"($co).pub"
    assert equal (glob ($pubs | path join *.pub) | length) 2
}

# A co-signer stands BESIDE an identity, so it cannot be the first key: that
# would leave a trust list nothing established, which is what --pubkey says
# deliberately.
@test
def "co-signer refuses when nothing is registered yet" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $tmp_dir | path join fresh

    mkdir $repo
    ^git init --object-format=sha256 -q $repo
    let co = $tmp_dir | path join lonely

    ^ssh-keygen -t ed25519 -f $co -N "" -q

    let err = try { init --repo $repo --co-signer $"($co).pub"; null } catch {|e| $e.msg }

    assert ($err != null) "a co-signer landed in a graph home with no identity"
    assert ($err | str contains "--pubkey")
    assert equal (glob ($repo | path join cybergraph multiproofs pubkeys *.pub) | length) 0
}

# The two flags answer different questions, so naming both names neither.
@test
def "pubkey and co-signer are alternatives" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let co = $in.tmp_dir | path join both

    ^ssh-keygen -t ed25519 -f $co -N "" -q
    assert error {|| init --repo $r.repo --pubkey $"($co).pub" --co-signer $"($co).pub" }
}

# A co-signer is a second key in the trust list, not a second identity: it adds
# its signature to a frozen seal snapshot so that forging one statement costs
# every device, which is the whole point of holding keys apart. The graph's own
# identity is this checkout's `user.signingKey` — the key `seal` signs the root
# with — so the key a record is authored under is the key that catalogues it.
@test
def "a co-signer in the trust list does not become the identity of the graph" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let home = $r.repo | path join cybergraph
    let mine = ls ($home | path join multiproofs pubkeys) | get name | first

    let co = $in.tmp_dir | path join co-signer

    ^ssh-keygen -t ed25519 -f $co -N "" -q
    init --repo $r.repo --co-signer $"($co).pub"
    assert equal (glob ($home | path join multiproofs pubkeys *.pub) | length) 2

    let rec = link add "cyber" "prophet" --repo $r.repo | get record

    assert equal $rec.signer (open --raw $mine | into binary | cid-v0)
}

# The other side of that rule, and it holds at every size of the trust list —
# ONE registered key is not an answer either. The list is where a foreign key
# belongs (upstream invites `alice.pub` into it to check her bundles), so a
# repo holding exactly one key someone else owns would otherwise author under
# her name with no error, and find out at `verify` that nothing binds.
@test
def "no configured signing key means no identity whatever the trust list holds" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let home = $r.repo | path join cybergraph

    ^git -C $r.repo config --unset user.signingKey

    let one = try { link add "cyber" "prophet" --repo $r.repo; null } catch {|e| $e.msg }

    assert ($one != null) "the single registered key answered for a checkout that names no signer"
    assert ($one | str contains "user.signingKey")

    let co = $in.tmp_dir | path join co-signer

    ^ssh-keygen -t ed25519 -f $co -N "" -q
    init --repo $r.repo --co-signer $"($co).pub"
    let two = try { link add "cyber" "prophet" --repo $r.repo; null } catch {|e| $e.msg }

    assert ($two != null) "a repo with two keys and no configured signer wrote a link anyway"
}

# Registration is what makes a signature readable: a record naming a signer the
# trust list holds no key for fails the binding at verify, bundle and import.
# Refused at the write, not three commands later.
@test
def "a signing key that is not registered cannot author" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let other = $in.tmp_dir | path join other

    ^ssh-keygen -t ed25519 -f $other -N "" -q
    ^git -C $r.repo config user.signingKey $other

    let err = try { link add "cyber" "prophet" --repo $r.repo; null } catch {|e| $e.msg }

    assert ($err != null) "a link was authored under a key the trust list does not hold"
    assert ($err | str contains "not registered")
}

@test
def "init is idempotent and a re-run reports without duplicating" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    init --repo $r.repo
    assert equal (glob ($r.repo | path join cybergraph multiproofs pubkeys *.pub) | length) 1
    assert (($r.repo | path join cybergraph certs) | path exists)
}

# `init` says its job is to establish the signer identity, so a run that
# establishes none has not done it.
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
    # And it refuses before claiming a layout: no certs/ to suggest otherwise.
    assert not (($repo | path join cybergraph certs) | path exists)
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
    assert (($repo | path join cybergraph certs) | path exists)
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
def "seal before init fails fast before anything is written" [] {
    let r = make-bare-repo $in.tmp_dir

    "hi\n" | save ($r.repo | path join readme.md)
    ^git -C $r.repo add -A

    let err = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($err != null) "seal ran without a registered pubkey"
    assert ($err | str contains "nu-cybergraph init")
    # Nothing mutated: no manifest, no root statement
    assert not (($r.repo | path join cybergraph multiproofs tree-hashes.csv) | path exists)
}

@test
def "in a nested graph home init puts everything under cybergraph by default" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    assert (($r.repo | path join cybergraph multiproofs pubkeys) | path exists)
    assert (($r.repo | path join cybergraph certs) | path exists)

    # An arbitrary user file at the repo root: tracked by git, untouched by
    # the graph — the seal manifest covers only the cybergraph/ subtree
    "arbitrary user file\n" | save ($r.repo | path join notes.md)
    ^git -C $r.repo add -A

    let born = link add $P1 $P2 --repo $r.repo --allow-missing

    assert ($born.path | str contains $"cybergraph(char path_sep)($born.record.signer)")
    let sealed = seal --repo $r.repo --no-stamp --allow-untracked-particles

    assert equal $sealed.newborn 1
    assert (($r.repo | path join cybergraph certs $born.record.signer $"($born.edge_cid).cert.json") | path exists)
    let manifest = open --raw ($r.repo | path join cybergraph multiproofs tree-hashes.csv)
        | from csv --no-infer

    assert ($manifest | where filepath == "notes.md" | is-empty)
    assert ($manifest | where filepath == $"($born.record.signer)/($born.edge_cid).json" | is-not-empty)

    # Discovery is implicit from here on: verify finds the nested home itself
    assert (verify $born.edge_cid --repo $r.repo | first | get valid)
}

@test
def "link add is idempotent on a repeat of the triple as one act in one file" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let born = link add $P1 $P2 --repo $r.repo --allow-missing

    # The record IS the triple, so a repeat is byte-identical: a no-op that
    # returns the same CID, not a second file or an error.
    let again = link add $P1 $P2 --repo $r.repo --allow-missing

    assert equal $again $born
    assert equal (glob ($r.repo | path join cybergraph $born.record.signer *.json) | length) 1
}

@test
def "link add refuses to treat a mismatched file at the triple own path as a repeat" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let born = link add $P1 $P2 --repo $r.repo --allow-missing

    swap-record $born.path (open --raw $born.path | from json | update cid_to $P3)

    # The path exists, but it is not this triple's own bytes — a repeat check
    # that only asked `path exists` would report success over a corrupted
    # store; `link add` must fail the same way `seal` does above.
    let err = try { link add $P1 $P2 --repo $r.repo --allow-missing; null } catch {|e| $e.msg }

    assert ($err != null) "corrupted file at the triple's own path was accepted as a repeat"
}

@test
def "seal refuses a link file that does not match its content address" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let born = link add $P1 $P2 --repo $r.repo --allow-missing

    swap-record $born.path (open --raw $born.path | from json | update cid_to $P3)

    let err = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($err != null) "seal signed a record that is not its own address"
    assert ($err | str contains $born.edge_cid) $"error should name the offending file: ($err)"
    # Aborted before multiproof wrote anything — no manifest, no certificate
    assert not (($r.repo | path join cybergraph multiproofs tree-hashes.csv) | path exists)
    assert not (($r.repo | path join cybergraph certs $born.record.signer $"($born.edge_cid).cert.json") | path exists)
}

@test
def "a record tampered after its birth seal aborts the next seal too" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let born = link add $P1 $P2 --repo $r.repo --allow-missing

    assert equal (seal --repo $r.repo --no-stamp --allow-untracked-particles | get newborn) 1

    # Every seal re-attests the whole catalogue, so the check covers links that
    # already have a certificate — not just the newborns of this seal
    swap-record $born.path (open --raw $born.path | from json | update cid_to $P3)
    let err = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($err != null) "a tampered record was re-attested by a later seal"
    assert ($err | str contains $born.edge_cid)
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

    let err = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

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

    let err = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($err != null) "seal accepted a key that is not registered"
    assert ($err | str contains $"init --pubkey ($other | path expand).pub")
    # These two asserts pass BECAUSE upstream asks its registration question
    # first: nu-multiproof's `seal` asks it at the top, ahead of the manifest
    # rewrite, so a refused seal leaves no manifest and no root statement
    # behind.
    assert not (($r.repo | path join cybergraph multiproofs tree-hashes.csv) | path exists)
    assert not (($r.repo | path join cybergraph multiproofs tree-root.txt) | path exists)
}

# A repeated seal is not a no-op, and this pins it as behaviour rather than as a
# comment. `seal` ends by writing `seals/<root12>/`, holding that seal's root
# statement and signature; because `seals/` is staged, the next seal catalogues
# that directory, so its manifest differs and its root differs. No fixpoint
# exists: the directory is named after a root computed from a tree that would
# have to already contain it.
#
# Pinned because two things rest on it. The documented cost — an empty seal
# spends a signature and, with stamping on, a calendar round trip — and the
# snapshot guard in `seal.nu`, which is safe only because a root never recurs.
# If someone drops `seals/` from the staging list, this test is what says the
# guard just became live code that has never run.
@test
def "a seal with nothing new still mints a new root" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    link add $P1 $P2 --repo $r.repo --allow-missing | ignore

    let seals = 1..4 | each {|_| seal --repo $r.repo --no-stamp --allow-untracked-particles }
    let roots = $seals | get sealed.merkle_root

    assert equal ($roots | uniq | length) 4 $"roots repeated across four seals: ($roots)"
    # Only the first seal has a link to certify — the other three add nothing but
    # their own snapshot, which is the whole point.
    assert equal ($seals | get newborn) [1 0 0 0]
    assert equal (list-dirs ($r.repo | path join cybergraph seals) | length) 4

    # And the growth those extra roots cost, as rows under seals/ in the manifest.
    # Three snapshots are catalogued by the time the fourth seal builds its
    # manifest — its own is written afterwards — at three rows each: the
    # directory, tree-root.txt, and ONE signature. The last is this repo's
    # single-signer case; a second registered key would make it four rows per
    # snapshot, because seal copies every `tree-root.txt.*.sig` it finds.
    let manifest = open --raw ($r.repo | path join cybergraph multiproofs tree-hashes.csv)
        | from csv --no-infer
    let under_seals = $manifest | where filepath =~ '^seals/'

    assert equal ($under_seals | length) 9 $"expected 3 snapshots at 3 rows each, got: ($under_seals | get filepath)"
}

# The counter's whole purpose: seals are named by root, so from any single
# statement a chain of four and a chain of three look alike. Reading them in
# order is what makes a missing one visible.
@test
def "the seal chain runs from genesis with no gaps" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    link add $P1 $P2 --repo $r.repo --allow-missing | ignore
    let roots = 1..4 | each {|_| seal --repo $r.repo --no-stamp --allow-untracked-particles } | get sealed.merkle_root

    let chain = seal chain --repo $r.repo

    assert equal ($chain | get seq) [0 1 2 3]
    assert equal ($chain | get root) $roots
    # Each seal names the root it superseded; the first names none.
    assert equal ($chain | get prev) (["genesis"] ++ ($roots | first 3))
}

@test
def "a seal chain missing a snapshot is refused and not reported short" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    link add $P1 $P2 --repo $r.repo --allow-missing | ignore
    let roots = 1..3 | each {|_| seal --repo $r.repo --no-stamp --allow-untracked-particles } | get sealed.merkle_root

    # Drop the middle seal's snapshot: every certificate born under that root
    # now verifies against nothing, which is a fact about the repo — so the
    # chain must raise rather than hand back two rows that look complete.
    rm --recursive ($r.repo | path join cybergraph seals ($roots | get 1 | str substring 0..11))
    let err = try { seal chain --repo $r.repo; null } catch {|e| $e.msg }

    assert str contains $err "seal chain breaks at seq"
}

# The largest gap of all: no snapshots at all. An empty table would read as
# "this graph has no seals", which is the one thing a wiped seals/ also looks
# like — so the absence is raised, not reported.
@test
def "a graph with no seals directory is refused and not reported empty" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let err = try { seal chain --repo $r.repo; null } catch {|e| $e.msg }

    assert str contains $err "no seals/ directory"
}

# Asking only whether something EXISTS at the cert path let any node there answer
# "already certified". Measured, for a directory and for an empty file alike:
# seal reported success with newborn=0, the link went uncertified but WAS
# catalogued under that root, and the next seal — once the node was gone — froze
# a certificate naming a LATER root. The birth invariant broken with no error.
#
# All three shapes in one test because they are one rule, and the rule is not
# "is it a file" but "is it the frozen proof for THIS link".
@test
def "a node that is not this links frozen proof is refused before anything is staged" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let born = link add $P1 $P2 --repo $r.repo --allow-missing
    let cert = $r.repo | path join cybergraph certs $born.record.signer $"($born.edge_cid).cert.json"

    mkdir ($cert | path dirname)

    # 1. a directory
    mkdir $cert
    "junk\n" | save --raw ($cert | path join filler.txt)
    let e1 = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($e1 != null) "seal reported success while the link went uncertified"
    assert ($e1 | str contains $born.edge_cid) $"the refusal should name the path in the way: ($e1)"
    # Refused BEFORE staging, so the recovery is just removing the node.
    assert ((^git -C $r.repo diff --cached --name-only | str trim) | is-empty) "the failed seal left certs/ staged"
    rm --recursive --force $cert

    # 2. an empty file — a truncated write or an interrupted move, and the more
    #    likely accident of the two
    "" | save --raw $cert
    let e2 = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($e2 != null) "an empty file passed as a frozen certificate"
    assert ($e2 | str contains $born.edge_cid)
    rm $cert

    # 3. a real proof, but for a different link
    let other = link add $P1 $P3 --repo $r.repo --allow-missing

    seal --repo $r.repo --no-stamp --allow-untracked-particles | ignore
    let other_cert = $r.repo | path join cybergraph certs $other.record.signer $"($other.edge_cid).cert.json"

    assert ($other_cert | path exists) "the fixture needs a genuine proof to misfile"
    rm $cert
    cp $other_cert $cert
    let e3 = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($e3 != null) "a proof for another link passed as this links certificate"
    assert ($e3 | str contains $other.edge_cid) $"the refusal should name the record actually certified: ($e3)"

    # And the repo still seals once the misfiled proof is gone: every refusal
    # above has to be recoverable by removing what was named, nothing more.
    rm $cert
    let ok = seal --repo $r.repo --no-stamp --allow-untracked-particles

    assert equal $ok.newborn 1
    assert equal (open $cert | get leaf.filepath) $"($born.record.signer)/($born.edge_cid).json"
}

# The one thing that distinguishes the two orderings of `seal`'s writes. On the
# success path the snapshot and the freeze loops produce byte-identical results
# whichever runs first, so only a failure INSIDE a loop can pin it — and the
# damage was never in the failure itself, it was in what the failure left behind.
#
# A gitignored link is the lever: `list-files` walks the filesystem and sees it,
# `merkle prove` walks the manifest (git ls-files) and does not, so the loop
# throws part-way through with at least one certificate already frozen.
@test
def "a freeze loop that fails still leaves the snapshot its certificates name" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let a = link add $P1 $P2 --repo $r.repo --allow-missing
    let b = link add $P1 $P3 --repo $r.repo --allow-missing

    # The loop takes links in listing order, so hiding the LAST one guarantees
    # the first is certified before the throw. Sorting here is what makes that
    # deterministic rather than a property of how `ls` happened to answer.
    let victim = [$a.edge_cid $b.edge_cid] | sort | last

    $"cybergraph/($a.record.signer)/($victim).json\n" | save --raw ($r.repo | path join .gitignore)

    let err = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($err != null) "merkle prove found a link that git does not track"
    assert ($err | str contains $victim) $"error should name the untracked link: ($err)"

    # The damage this ordering removes: a certificate frozen under a root whose
    # snapshot was never written, while tree-root.txt had already moved on. The
    # certificate names its root, and that root must still be on disk — otherwise
    # `bundle` and `verify` for this link are dead and no re-seal can revive them,
    # because the retry mints a different root.
    let frozen = list-files ($r.repo | path join cybergraph certs) --recursive --suffix ".cert.json"

    assert ($frozen | is-not-empty) "the loop threw before freezing anything — the lever missed"
    for c in $frozen {
        let named = open $c | get root
        let snap = $r.repo | path join cybergraph seals ($named | str substring 0..<12)

        assert ($snap | path exists) $"certificate ($c | path basename) names root ($named) with no snapshot"
        assert (($snap | path join tree-root.txt) | path exists) $"snapshot ($named) holds no root statement"
    }
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

# The same rule for `mv`, and for the same reason: seal's freeze loops move a
# proof into `certs/`, and a proof frozen at birth is the link's earliest
# provable time bound — rewriting one moves that bound later with no error.
#
# Tested here rather than through `seal`, following the copy helpers above: at
# the seal sites the only shape that still reaches this guard is the race
# between the newborn filter and the move, which a test cannot stage in-process.
#
# All three occupied shapes, because `mv` destroys differently in each: over a
# file it clobbers, over a directory it moves the file INSIDE, and over a
# symlink it replaces the link node with a regular file.
@test
def "move-file refuses every shape of an occupied destination" [] {
    let tmp_dir = $in.tmp_dir
    let src = $tmp_dir | path join proof.json

    "incoming\n" | save --force --raw $src
    let frozen = $tmp_dir | path join frozen.cert.json

    "the birth proof\n" | save --raw $frozen
    let e1 = try { move-file $src $frozen; null } catch {|e| $e.msg }

    assert ($e1 != null) "move-file clobbered a frozen file"
    assert equal (open --raw $frozen) "the birth proof\n"
    assert ($src | path exists) "the source was consumed by a refused move"

    "incoming\n" | save --force --raw $src
    let occupied_dir = $tmp_dir | path join taken.cert.json

    mkdir $occupied_dir
    let e2 = try { move-file $src $occupied_dir; null } catch {|e| $e.msg }

    assert ($e2 != null) "move-file moved a proof inside a directory standing at the destination"
    assert ($e2 | str contains "dir") $"the refusal should name what is in the way: ($e2)"
    assert (list-files $occupied_dir | is-empty) "a proof landed inside the directory"

    "incoming\n" | save --force --raw $src
    let dangling = $tmp_dir | path join gone.cert.json

    ^ln -s ($tmp_dir | path join nowhere) $dangling
    # This is the case that decides `path type` over `path exists`: an
    # exists-based guard reads a dangling link as free, and `mv` then replaces
    # the link node with a regular file. So the assertion is that the link is
    # STILL a link afterwards — `path exists` alone cannot express the defect.
    assert not ($dangling | path exists) "the fixture is not dangling — the test proves nothing"
    let e3 = try { move-file $src $dangling; null } catch {|e| $e.msg }

    assert ($e3 != null) "move-file consumed a dangling symlink"
    assert equal ($dangling | path type) "symlink" "the symlink node was replaced by the move"

    # And it still moves when the destination is genuinely free — the refusal
    # must not have become total.
    "incoming\n" | save --force --raw $src
    let free = $tmp_dir | path join fresh.cert.json

    move-file $src $free
    assert equal (open --raw $free) "incoming\n"
    assert not ($src | path exists) "the source survived a completed move"
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

# The pre-seal sweep walks receipts/ by `receipt-files`' rule — CID-named
# author directories only — while staging git-adds receipts/ wholesale. So a
# stray at the top of receipts/ (a flat file, a hand-named directory) would be
# signed into every manifest unvalidated and never frozen. Same recovery
# contract as the certs sweep: refused before staging, removing the node is the
# whole fix.
@test
def "a stray under receipts is refused before anything is staged" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    link add $P1 $P2 --repo $r.repo --allow-missing | ignore
    let receipts = $r.repo | path join cybergraph receipts

    # 1. a flat receipt — valid-looking bytes, wrong level
    mkdir $receipts
    '{"link":"x"}' | save --raw ($receipts | path join $"($P1).receipt.json")
    let e1 = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($e1 != null) "seal signed a receipt the sweep never validated"
    assert ($e1 | str contains $"($P1).receipt.json") $"the refusal should name the stray: ($e1)"
    assert ((^git -C $r.repo diff --cached --name-only | str trim) | is-empty) "the failed seal left receipts/ staged"
    rm ($receipts | path join $"($P1).receipt.json")

    # 2. a hand-named author directory — everything under it is invisible to
    #    the sweep, whatever it holds
    mkdir ($receipts | path join alice)
    '{"link":"x"}' | save --raw ($receipts | path join alice $"($P1).receipt.json")
    let e2 = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($e2 != null) "a non-CID author directory was signed unchecked"
    assert ($e2 | str contains "alice") $"the refusal should name the stray directory: ($e2)"

    # And the repo still seals once the strays are gone.
    rm --recursive ($receipts | path join alice)
    let ok = seal --repo $r.repo --no-stamp --allow-untracked-particles

    assert equal $ok.newborn 1
}

# The tamper class this layout allows: the signer is in the file's path, not
# its bytes, so a sealed <signerA>/<edge>.json moved into another
# valid-CID directory keeps canonical bytes AND a matching filename. The binding of
# pair to signer is the seal's (the path enters the signed root), so a
# relocated file must earn no credit anywhere: not from its old certificate,
# not at its new path, and not from the next seal.
@test
def "a sealed edge file moved to another signer directory earns no credit" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    let own = link add $P1 $P2 --repo $r.repo --allow-missing
    let adhoc = link add $P1 $P2 --repo $r.repo --allow-missing --keyless-signer alice

    seal --repo $r.repo --no-stamp --allow-untracked-particles | ignore
    assert equal (verify $own.edge_cid --repo $r.repo | length) 2

    # Relocate the ad-hoc copy into a fresh directory named by a valid CID —
    # its position with it, and the position's frozen proof dropped.
    #
    # That extra care is what keeps this test about the relocation. Moving the
    # record alone leaves it counted by no run, so the position bijection
    # refuses first and the refusal below is never reached; moving the position
    # too satisfies the bijection (the new run is [0], the vacated one empty).
    let home = $r.repo | path join cybergraph

    mkdir ($home | path join $P3)
    mv ($home | path join $adhoc.record.signer $"($adhoc.edge_cid).json") ($home | path join $P3 $"($adhoc.edge_cid).json")
    mkdir ($home | path join order $P3)
    mv (order-path $home $adhoc.record.signer $adhoc.edge_cid) (order-path $home $P3 $adhoc.edge_cid)
    rm (order-cert-path $home $adhoc.record.signer $adhoc.edge_cid)

    # The old certificate points at an absent file, the new path has none:
    # the moved copy drops out of the full query instead of riding either.
    let rows = verify $own.edge_cid --repo $r.repo

    assert equal ($rows | get record.signer) [$own.record.signer]
    let err = try { verify $own.edge_cid --repo $r.repo --signer $P3; null } catch {|e| $e.msg }

    assert ($err | str contains "no birth certificate yet") $"the relocated copy must read as never sealed, got: ($err)"

    # And the next seal refuses outright — the manifest still tracks the
    # vacated path — rather than certifying the relocation as a new birth.
    let sealed = try { seal --repo $r.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($sealed != null) "seal certified a relocated link file"
    assert ($sealed | str contains $"($adhoc.record.signer)/($adhoc.edge_cid).json") $"the refusal should name the vacated path: ($sealed)"
}

# --external-signer: the first run stops before anything cybergraph-specific is
# written, so the second run computes the same root and the signature made over
# the first run's statement still stands. ssh-keygen stands in for the device.
@test
def "an external signer seal freezes nothing until the signature arrives" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo
    link add $P1 $P2 --repo $r.repo --allow-missing | ignore
    seal --repo $r.repo --no-stamp --allow-untracked-particles
    link add $P2 $P3 --repo $r.repo --allow-missing | ignore

    let graph = $r.repo | path join cybergraph
    let statement = $graph | path join multiproofs tree-root.txt
    let sig = $"($statement).(open --raw $"($r.key).pub" | pubkey fingerprint).sig"
    let seals_before = list-dirs ($graph | path join seals)

    let waiting = seal --repo $r.repo --no-stamp --allow-untracked-particles --external-signer

    assert ("awaiting_signature" in $waiting.sealed)
    assert equal (list-dirs ($graph | path join seals)) $seals_before "a snapshot was written for a root nobody signed"
    assert equal (list-files ($graph | path join certs) --recursive --suffix ".json" | length) 1 "a certificate was frozen under an unsigned root"

    open --raw $statement | ^ssh-keygen -Y sign -q -f $r.key -n file | save --raw $sig
    let signed = open --raw $statement
    let sealed = seal --repo $r.repo --no-stamp --allow-untracked-particles --external-signer

    assert equal (open --raw $statement) $signed "the second run computed another root, so the signature went stale"
    assert equal $sealed.newborn 1
    assert ($sealed.snapshot | path join ($sig | path basename) | path exists) "the snapshot misses the outside signature"
}

# The case met in a linked worktree: the inherited user.signingKey names a key
# that exists only on another machine, and the refusal has to say where to fix it.
@test
def "a signing key that is not on this machine names the config to fix" [] {
    let r = make-bare-repo $in.tmp_dir

    init --repo $r.repo --pubkey $"($r.key).pub"
    ^git -C $r.repo config user.signingKey ($in.tmp_dir | path join elsewhere.pub)
    let err = try { link add $P1 $P2 --repo $r.repo --allow-missing; null } catch {|e| $e.msg }

    assert ($err | str contains "signing key not on this machine")
    assert ($err | str contains "git config user.signingKey")
    assert ($err | str contains "--worktree")
}
