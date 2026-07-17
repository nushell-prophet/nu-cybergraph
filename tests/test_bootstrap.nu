# Bootstrap contracts: init is idempotent; seal refuses to run half-way when
# the neuron identity is not registered yet.
use std/assert
use std/testing *

use ../nu-cybergraph/init.nu
use ../nu-cybergraph/seal.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/verify.nu

const P1 = "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
const P2 = "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"

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

@test
def "seal before init fails fast, before anything is written" [] {
    let r = make-bare-repo $in.tmp_dir
    "hi\n" | save ($r.repo | path join readme.md)
    ^git -C $r.repo add -A

    let err = try { seal --repo $r.repo --no-stamp --no-root-cid; null } catch {|e| $e.msg }
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

    let born = link add $P1 $P2 --repo $r.repo --claimed-at "2026-07-16T00:00:00+00:00"
    assert ($born.path | str contains $"cybergraph(char path_sep)links")
    let sealed = seal --repo $r.repo --no-stamp --no-root-cid
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
def "link add refuses a duplicate triple unless --reassert" [] {
    let r = make-bare-repo $in.tmp_dir
    init --repo $r.repo
    let born = link add $P1 $P2 --repo $r.repo --claimed-at "2026-07-16T00:00:00+00:00"

    # Fresh claimed_at, same triple: refused, names the existing record
    let err = try { link add $P1 $P2 --repo $r.repo --claimed-at "2026-07-17T00:00:00+00:00"; null } catch {|e| $e.msg }
    assert ($err != null) "duplicate triple was recorded"
    assert ($err | str contains $born.cid)
    assert ($err | str contains "--reassert")

    # Deliberate re-assertion: a second record next to the first
    let again = link add $P1 $P2 --repo $r.repo --claimed-at "2026-07-17T00:00:00+00:00" --reassert
    assert ($again.cid != $born.cid)
    assert equal (glob ($r.repo | path join cybergraph links *.json) | length) 2

    # Byte-identical record stays refused even with --reassert
    let same = try { link add $P1 $P2 --repo $r.repo --claimed-at "2026-07-16T00:00:00+00:00" --reassert; null } catch {|e| $e.msg }
    assert ($same != null) "byte-identical record was recorded twice"
    assert ($same | str contains "already exists")
}

@test
def "seal with --key but no .pub next to it fails fast" [] {
    let r = make-bare-repo $in.tmp_dir
    init --repo $r.repo
    let other = $in.tmp_dir | path join other-key
    ^ssh-keygen -t ed25519 -f $other -N "" -q
    rm $"($other).pub"

    let err = try { seal --repo $r.repo --key $other --no-stamp --no-root-cid; null } catch {|e| $e.msg }
    assert ($err != null) "seal ran without the public key present"
    assert ($err | str contains $"($other).pub")
    assert not (($r.repo | path join cybergraph multiproofs tree-hashes.csv) | path exists)
}

@test
def "seal with an unregistered --key names the fix" [] {
    let r = make-bare-repo $in.tmp_dir
    init --repo $r.repo
    let other = $in.tmp_dir | path join other-key
    ^ssh-keygen -t ed25519 -f $other -N "" -q

    let err = try { seal --repo $r.repo --key $other --no-stamp --no-root-cid; null } catch {|e| $e.msg }
    assert ($err != null) "seal accepted a key that is not registered"
    assert ($err | str contains $"init --pubkey ($other).pub")
    assert not (($r.repo | path join cybergraph multiproofs tree-hashes.csv) | path exists)
}
