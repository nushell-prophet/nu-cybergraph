# Bootstrap contracts: init is idempotent; seal refuses to run half-way when
# the neuron identity is not registered yet.
use std/assert
use std/testing *

use ../nu-cybergraph/init.nu
use ../nu-cybergraph/seal.nu

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
    assert equal (glob ($r.repo | path join multiproofs pubkeys *.pub) | length) 1
    assert (($r.repo | path join links) | path exists)
    assert (($r.repo | path join certs) | path exists)
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
    assert not (($r.repo | path join multiproofs tree-hashes.csv) | path exists)
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
    assert not (($r.repo | path join multiproofs tree-hashes.csv) | path exists)
}
