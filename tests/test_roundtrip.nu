# End-to-end: neuron A births a link, seals, exports the bundle; neuron B
# verifies and imports it offline. Ports the bostrom-journal bj003 smoke
# experiment into a pinned test. All seals run --no-stamp --no-root-cid
# (offline); OTS is exercised by nu-multiproof's own suite.
use std/assert
use std/testing *

use ../nu-cybergraph/init.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/seal.nu
use ../nu-cybergraph/bundle.nu
use ../nu-cybergraph/import.nu
use ../nu-cybergraph/verify.nu
use ../nu-cybergraph/_verify-helpers.nu [verify-bundle]
use ../nu-cybergraph/_deps.nu [cid-v0]

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

# A neuron repo: sha256 git backend (the spec's recommendation), one ed25519
# key registered as both git signing key and cybergraph identity.
def make-neuron [tmp_dir: path name: string]: nothing -> record {
    let repo = $tmp_dir | path join $name
    mkdir $repo
    ^git init --object-format=sha256 -q $repo
    ^git -C $repo config user.name $name
    ^git -C $repo config user.email $"($name)@test"
    let key = $tmp_dir | path join $"key-($name)"
    ^ssh-keygen -t ed25519 -f $key -N "" -C $name -q
    ^git -C $repo config user.signingKey $key
    init --repo $repo
    {repo: $repo home: ($repo | path join cybergraph) key: $key pub: $"($key).pub"}
}

@test
def "birth, seal, bundle, import, verify — the full link journey" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"

    # Birth + seal: certificate frozen, root snapshot archived
    let born = link add $P1 $P2 --repo $a.repo --claimed-at "2026-07-16T00:00:00+00:00"
    let sealed = seal --repo $a.repo --no-stamp --no-root-cid
    assert equal $sealed.newborn 1
    assert (($a.home | path join certs $"($born.cid).cert.json") | path exists)
    assert (($sealed.snapshot | path join tree-root.txt) | path exists)
    assert ((glob ($sealed.snapshot | path join "tree-root.txt.*.sig") | length) == 1)

    # Own-link verify goes through the same bundle path a stranger would use
    let own = verify $born.cid --repo $a.repo
    assert $own.valid
    assert $own.neuron.bound
    assert equal $own.record $born.record
    assert equal $own.ots.status "absent"

    # Export and import into B
    let bundle_dir = bundle $born.cid --repo $a.repo --out ($tmp_dir | path join out-bundle)
    let b = make-neuron $tmp_dir "b"
    let imported = import $bundle_dir --repo $b.repo
    assert equal $imported.neuron $born.record.neuron
    assert (($b.home | path join imported $born.record.neuron $born.cid) | path exists)

    # B verifies its copy offline, by CID alone
    let checks = verify $born.cid --repo $b.repo
    assert equal ($checks | length) 1
    assert ($checks | first | get valid)
    assert ($checks | first | get neuron.bound)

    # B's own seal catalogues the imported bundle — the custody layer:
    # "this neuron held the link no later than block K"
    seal --repo $b.repo --no-stamp --no-root-cid | ignore
    let b_manifest = open --raw ($b.home | path join multiproofs tree-hashes.csv)
        | from csv --no-infer
    let bundled_record = $"imported/($born.record.neuron)/($born.cid)/links/($born.cid).json"
    assert ($b_manifest | where filepath == $bundled_record | is-not-empty)

    # A second seal must not touch the frozen certificate (birth, not latest)
    let cert = $a.home | path join certs $"($born.cid).cert.json"
    let before = open --raw $cert | hash sha256
    link add $P2 $P1 --repo $a.repo --claimed-at "2026-07-16T01:00:00+00:00"
    let sealed2 = seal --repo $a.repo --no-stamp --no-root-cid
    assert equal $sealed2.newborn 1
    assert equal (open --raw $cert | hash sha256) $before
    # ...and the old link still verifies against its archived root
    assert (verify $born.cid --repo $a.repo).valid
}

@test
def "forged authorship is refused: neuron CID of a key that never signed" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"

    # The record claims key-mallory's identity, but the seal is signed by a's key
    let mallory = $tmp_dir | path join key-mallory
    ^ssh-keygen -t ed25519 -f $mallory -N "" -C mallory -q
    let mallory_cid = open --raw $"($mallory).pub" | into binary | cid-v0
    let born = link add $P1 $P2 --repo $a.repo --neuron $mallory_cid --claimed-at "2026-07-16T00:00:00+00:00"
    seal --repo $a.repo --no-stamp --no-root-cid | ignore

    let bundle_dir = bundle $born.cid --repo $a.repo --out ($tmp_dir | path join out-bundle)
    let v = verify-bundle $bundle_dir
    assert $v.structure_valid
    assert not $v.neuron.bound
    assert not $v.valid

    let b = make-neuron $tmp_dir "b"
    assert error {|| import $bundle_dir --repo $b.repo }
}

@test
def "non-canonical pubkey file in a bundle is refused" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --claimed-at "2026-07-16T00:00:00+00:00"
    seal --repo $a.repo --no-stamp --no-root-cid | ignore
    let bundle_dir = bundle $born.cid --repo $a.repo --out ($tmp_dir | path join out-bundle)

    # Re-adding a comment keeps the key material — the signature would still
    # verify and the neuron would merely unbind. The canonical-form check must
    # refuse the bundle outright instead, naming the malformed file.
    let pub = glob ($bundle_dir | path join multiproofs pubkeys *.pub) | first
    let raw = open --raw $pub | str trim
    $"($raw) mallory\n" | save --raw --force $pub
    assert error {|| verify-bundle $bundle_dir }
}

@test
def "tampered record in a bundle fails self-addressing" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --claimed-at "2026-07-16T00:00:00+00:00"
    seal --repo $a.repo --no-stamp --no-root-cid | ignore
    let bundle_dir = bundle $born.cid --repo $a.repo --out ($tmp_dir | path join out-bundle)

    let rec_file = $bundle_dir | path join links $"($born.cid).json"
    open --raw $rec_file | str replace $P2 $P1 | save --raw --force $rec_file
    assert error {|| verify-bundle $bundle_dir }
}
