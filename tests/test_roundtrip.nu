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

    # Own-link verify goes through the same bundle path a stranger would use;
    # the result is a one-row table — same shape as the imported case below
    let owns = verify $born.cid --repo $a.repo
    assert equal ($owns | length) 1
    let own = $owns | first
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
    assert (verify $born.cid --repo $a.repo | first | get valid)
}

# The repo's neuron identity: CID of its single registered (canonical) pubkey
def neuron-cid [home: path]: nothing -> string {
    open --raw (glob ($home | path join multiproofs pubkeys *.pub) | first) | into binary | cid-v0
}

@test
def "custody chain: each re-export appends a provable, ordered layer" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --claimed-at "2026-07-16T00:00:00+00:00"
    seal --repo $a.repo --no-stamp --no-root-cid | ignore
    let a_out = bundle $born.cid --repo $a.repo --out ($tmp_dir | path join a-out)

    # B imports the birth bundle: receipt written, first custodian chains to nothing
    let b = make-neuron $tmp_dir "b"
    let b_imported = import $a_out --repo $b.repo
    assert equal $b_imported.custody 0
    let b_receipt = open --raw $b_imported.receipt | from json
    assert equal $b_receipt.prev null
    assert equal $b_receipt.custodian (neuron-cid $b.home)

    # Re-export before sealing must refuse: custody is provable only once sealed
    assert error {|| bundle $born.cid --repo $b.repo --out ($tmp_dir | path join too-early) }

    let sealed_b = seal --repo $b.repo --no-stamp --no-root-cid
    assert equal $sealed_b.receipts 1
    assert (($b.home | path join receipts $"($born.cid).receipt.cert.json") | path exists)
    let b_out = bundle $born.cid --repo $b.repo --out ($tmp_dir | path join b-out)

    # C imports B's re-export: verifies layer 1, chains its own receipt to B's
    let c = make-neuron $tmp_dir "c"
    let c_imported = import $b_out --repo $c.repo
    assert equal $c_imported.custody 1
    let c_receipt = open --raw $c_imported.receipt | from json
    let b_layer_receipt = $b_out | path join custody $"1-($b_receipt.custodian | str substring 0..11)" receipts $"($born.cid).receipt.json"
    assert equal $c_receipt.prev (open --raw $b_layer_receipt | hash sha256)

    seal --repo $c.repo --no-stamp --no-root-cid | ignore
    let c_out = bundle $born.cid --repo $c.repo --out ($tmp_dir | path join c-out)

    # A stranger verifies the whole dissemination path offline: A authored,
    # then B held it, then C — ordered by the receipt chain
    let v = verify-bundle $c_out
    assert $v.valid
    assert $v.neuron.bound
    assert equal ($v.custody | get index) [1 2]
    assert equal ($v.custody | get custodian) [(neuron-cid $b.home) (neuron-cid $c.home)]
    assert ($v.custody | all { $in.bound })

    # ...and the chain survives a fourth hop's import + repo-level verify
    let d = make-neuron $tmp_dir "d"
    import $c_out --repo $d.repo | ignore
    let d_check = verify $born.cid --repo $d.repo | first
    assert $d_check.valid
    assert equal ($d_check.custody | length) 2

    # Stripping a middle layer breaks the chain loudly (indices no longer
    # start at 1, and C's prev would point at a missing receipt)
    let stripped = $tmp_dir | path join stripped
    cp -r $c_out $stripped
    rm -r ($stripped | path join custody $"1-($b_receipt.custodian | str substring 0..11)")
    assert error {|| verify-bundle $stripped }

    # Tampering with a layer's receipt bytes fails its content proof AND the
    # next layer's prev hash — the chain pins every receipt's exact bytes
    let tampered = $tmp_dir | path join tampered
    cp -r $c_out $tampered
    let target = $tampered | path join custody $"1-($b_receipt.custodian | str substring 0..11)" receipts $"($born.cid).receipt.json"
    open --raw $target | str replace --regex '"received_at":"\d{4}' '"received_at":"2099' | save --raw --force $target
    let tv = verify-bundle $tampered
    assert not $tv.valid
    assert not ($tv.custody | first | get valid)
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
