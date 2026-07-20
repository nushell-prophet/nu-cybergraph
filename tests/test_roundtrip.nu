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
use ../nu-cybergraph/_deps/cid-v0.nu [cid-v0]

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
    let born = link add $P1 $P2 --repo $a.repo
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
    link add $P2 $P1 --repo $a.repo
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
    let born = link add $P1 $P2 --repo $a.repo
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

# Not "handoff: …" because: a leading `word:` makes nutest's generated
# `execute: { <name> }` block parse as a record and the whole suite fails.
@test
def "handoff makes direction a signed claim, woven into the custody chain" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"
    let b = make-neuron $tmp_dir "b"
    let c = make-neuron $tmp_dir "c"

    let born = link add $P1 $P2 --repo $a.repo
    seal --repo $a.repo --no-stamp --no-root-cid | ignore

    # A hands the birth bundle to B by neuron CID: signed handoff at the root
    let a_out = bundle $born.cid --repo $a.repo --out ($tmp_dir | path join a-out) --to (neuron-cid $b.home)
    let root_handoff = $a_out | path join $"($born.cid).handoff.json"
    assert ($root_handoff | path exists)
    let av = verify-bundle $a_out
    assert $av.valid
    assert equal $av.handed_to (neuron-cid $b.home)

    # Wrong recipient: mallory can hold the bundle but cannot become a custodian
    let m = make-neuron $tmp_dir "m"
    assert error {|| import $a_out --repo $m.repo }

    # Pinned residual (accepted, README "Three honest limits"): the refusal
    # above is a fail-fast for honest flows, not a boundary — whoever holds
    # the bytes can strip the unsealed handoff and import the bundle as an
    # open one. Only the recipient's SEAL makes a handoff permanent (the
    # strip-after-seal case is caught, tested at the end of this test).
    let laundered = $tmp_dir | path join laundered
    cp -r $a_out $laundered
    rm ($laundered | path join $"($born.cid).handoff.json")
    glob ($laundered | path join $"($born.cid).handoff.json.*.sig") | each {|f| rm $f }
    let m_imported = import $laundered --repo $m.repo

    # Forged custodian at the custody level: mallory edits their receipt to
    # claim B's identity before sealing. The seal signs the forged bytes fine —
    # only the binding check (custodian CID vs the validly-signing key) refuses.
    open --raw $m_imported.receipt
    | str replace (neuron-cid $m.home) (neuron-cid $b.home)
    | save --raw --force $m_imported.receipt
    seal --repo $m.repo --no-stamp --no-root-cid | ignore
    let m_out = bundle $born.cid --repo $m.repo --out ($tmp_dir | path join m-out)
    let mv = verify-bundle $m_out
    assert not $mv.valid
    assert not ($mv.custody | first | get bound)

    # The named recipient imports; the receipt pins the handoff's hash
    let b_imported = import $a_out --repo $b.repo
    let b_receipt = open --raw $b_imported.receipt | from json
    assert equal $b_receipt.handoff (open --raw $root_handoff | hash sha256)

    seal --repo $b.repo --no-stamp --no-root-cid | ignore
    let b_out = bundle $born.cid --repo $b.repo --out ($tmp_dir | path join b-out) --to (neuron-cid $c.home)

    import $b_out --repo $c.repo | ignore
    seal --repo $c.repo --no-stamp --no-root-cid | ignore
    # C re-exports openly (no recipient): legal, the chain just ends unaddressed
    let c_out = bundle $born.cid --repo $c.repo --out ($tmp_dir | path join c-out)

    let v = verify-bundle $c_out
    assert $v.valid
    assert equal $v.handoff.to (neuron-cid $b.home)
    assert equal ($v.custody | first | get handoff | get to) (neuron-cid $c.home)
    assert equal ($v.custody | last | get handoff) null
    assert equal $v.handed_to null

    # Stripping the author's handoff breaks B's sealed receipt — detected
    let stripped = $tmp_dir | path join stripped
    cp -r $c_out $stripped
    rm ($stripped | path join $"($born.cid).handoff.json")
    glob ($stripped | path join $"($born.cid).handoff.json.*.sig") | each {|f| rm $f }
    assert not (verify-bundle $stripped | get valid)
}

@test
def "forged authorship is refused: neuron CID of a key that never signed" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"

    # The record claims key-mallory's identity, but the seal is signed by a's key
    let mallory = $tmp_dir | path join key-mallory
    ^ssh-keygen -t ed25519 -f $mallory -N "" -C mallory -q
    let mallory_cid = open --raw $"($mallory).pub" | into binary | cid-v0
    let born = link add $P1 $P2 --repo $a.repo --neuron $mallory_cid
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
    let born = link add $P1 $P2 --repo $a.repo
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
    let born = link add $P1 $P2 --repo $a.repo
    seal --repo $a.repo --no-stamp --no-root-cid | ignore
    let bundle_dir = bundle $born.cid --repo $a.repo --out ($tmp_dir | path join out-bundle)

    let rec_file = $bundle_dir | path join links $"($born.cid).json"
    open --raw $rec_file | str replace $P2 $P1 | save --raw --force $rec_file
    assert error {|| verify-bundle $bundle_dir }
}

const FAKE_SHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

# check-handoff's two defense paths, at the bundle root and in a custody
# layer: the claims must match the link/holder/receipt the file travels
# with, and the bytes must carry a valid signature by the `from` neuron.
# Each scenario tampers exactly one thing on a fresh copy; the asserted
# error fragment pins WHICH check fired, not its wording.
@test
def "a handoff that is tampered, unsigned, or misclaiming is refused" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"
    let b = make-neuron $tmp_dir "b"
    let born = link add $P1 $P2 --repo $a.repo
    seal --repo $a.repo --no-stamp --no-root-cid | ignore
    let a_out = bundle $born.cid --repo $a.repo --out ($tmp_dir | path join a-out) --to (neuron-cid $b.home)
    let handoff_name = $"($born.cid).handoff.json"

    # Tampered signed bytes: the claims stay coherent (handed_at is not a
    # checked claim), only the signature no longer covers the file
    let bad_sig = $tmp_dir | path join bad-sig
    cp -r $a_out $bad_sig
    let f = $bad_sig | path join $handoff_name
    open --raw $f | str replace --regex '"handed_at":"\d{4}' '"handed_at":"2099' | save --raw --force $f
    let v = verify-bundle $bad_sig
    assert not $v.valid
    assert not $v.handoff.valid
    assert ($v.error | str contains "no valid signature")
    # a handoff that fails verification must not name an addressee
    assert equal $v.handed_to null
    assert error {|| import $bad_sig --repo $b.repo }

    # Signature stripped but the handoff kept: a claim without proof
    let no_sig = $tmp_dir | path join no-sig
    cp -r $a_out $no_sig
    glob ($no_sig | path join $"($handoff_name).*.sig") | each {|s| rm $s }
    let v2 = verify-bundle $no_sig
    assert not $v2.valid
    assert ($v2.error | str contains "no valid signature")

    # `from` claims an identity other than the holder it travels with
    let wrong_from = $tmp_dir | path join wrong-from
    cp -r $a_out $wrong_from
    let f3 = $wrong_from | path join $handoff_name
    open --raw $f3 | str replace $born.record.neuron $P1 | save --raw --force $f3
    let v3 = verify-bundle $wrong_from
    assert not $v3.valid
    assert ($v3.error | str contains "handoff claims do not match")

    # The author's handoff must pin receipt null — a non-null hash mismatches
    let wrong_receipt = $tmp_dir | path join wrong-receipt
    cp -r $a_out $wrong_receipt
    let f4 = $wrong_receipt | path join $handoff_name
    open --raw $f4 | str replace '"receipt":null' $'"receipt":"($FAKE_SHA)"' | save --raw --force $f4
    let v4 = verify-bundle $wrong_receipt
    assert not $v4.valid
    assert ($v4.error | str contains "handoff claims do not match")

    # Same checks on a custody layer's outgoing handoff: B imports, seals,
    # re-exports handed to C — then the layer handoff's `receipt` is edited
    # to a hash that is not B's receipt
    let c = make-neuron $tmp_dir "c"
    import $a_out --repo $b.repo | ignore
    seal --repo $b.repo --no-stamp --no-root-cid | ignore
    let b_out = bundle $born.cid --repo $b.repo --out ($tmp_dir | path join b-out) --to (neuron-cid $c.home)
    assert (verify-bundle $b_out | get valid)

    let wrong_layer = $tmp_dir | path join wrong-layer
    cp -r $b_out $wrong_layer
    let lf = $wrong_layer | path join custody $"1-(neuron-cid $b.home | str substring 0..11)" $handoff_name
    open --raw $lf | str replace --regex '"receipt":"[0-9a-f]{64}"' $'"receipt":"($FAKE_SHA)"' | save --raw --force $lf
    let lv = verify-bundle $wrong_layer
    assert not $lv.valid
    assert not ($lv.custody | first | get handoff | get valid)
    assert ($lv.error | str contains "handoff claims do not match")
    assert equal $lv.handed_to null
}

# The layer dirname is transport only — verification must refuse whenever
# the name and the verified receipt disagree, however the name was forged.
@test
def "custody layer names cannot lie — forged dirname, duplicated custodian, renumbered index" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo
    seal --repo $a.repo --no-stamp --no-root-cid | ignore
    let a_out = bundle $born.cid --repo $a.repo --out ($tmp_dir | path join a-out)
    let b = make-neuron $tmp_dir "b"
    import $a_out --repo $b.repo | ignore
    seal --repo $b.repo --no-stamp --no-root-cid | ignore
    let b_out = bundle $born.cid --repo $b.repo --out ($tmp_dir | path join b-out)
    let a12 = neuron-cid $a.home | str substring 0..11
    let b12 = neuron-cid $b.home | str substring 0..11

    # Well-formed dirname claiming another neuron: dirname-vs-receipt throw
    let forged = $tmp_dir | path join forged
    cp -r $b_out $forged
    mv ($forged | path join custody $"1-($b12)") ($forged | path join custody $"1-($a12)")
    let err = try { verify-bundle $forged | ignore; null } catch {|e| $e.msg }
    assert ($err != null and ($err | str contains "does not match its receipt's custodian"))

    # Same custodian twice: layer 2 is a byte-copy of layer 1, so its name
    # and binding check out — its receipt chains to nothing while the chain
    # demands layer 1's hash. Refused by `prev`, not by naming.
    let dup = $tmp_dir | path join dup
    cp -r $b_out $dup
    cp -r ($dup | path join custody $"1-($b12)") ($dup | path join custody $"2-($b12)")
    let v = verify-bundle $dup
    assert not $v.valid
    assert ($v.custody | first | get valid)
    assert (($v.custody | last | get error) | str contains "prev hash does not match")

    # Renumbering the only layer: indices must be contiguous from 1 — this
    # pins the non-strip contiguity case (the middle-strip case is covered
    # in the custody chain test above)
    let renum = $tmp_dir | path join renum
    cp -r $b_out $renum
    mv ($renum | path join custody $"1-($b12)") ($renum | path join custody $"2-($b12)")
    let err2 = try { verify-bundle $renum | ignore; null } catch {|e| $e.msg }
    assert ($err2 != null and ($err2 | str contains "not contiguous"))
}

# The signing key resolves before the destination dir is created: a key error
# after assembly used to leave a complete-looking bundle whose handoff was
# unsigned, and the retry with --key was blocked by "destination already exists".
@test
def "bundle --to without a signing key fails before writing anything" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo
    seal --repo $a.repo --no-stamp --no-root-cid | ignore

    ^git -C $a.repo config --unset user.signingKey
    let dest = $tmp_dir | path join out
    assert error {|| bundle $born.cid --repo $a.repo --out $dest --to $P1 }
    assert not ($dest | path exists)

    # ...so the retry with an explicit --key finds the destination free
    let out = bundle $born.cid --repo $a.repo --out $dest --to $P1 --key $a.key
    assert (($out | path join $"($born.cid).handoff.json") | path exists)
    assert ((glob ($out | path join $"($born.cid).handoff.json.*.sig") | length) == 1)
}

# The writer's exit self-check: whatever breaks assembly (the observed case
# was an interior `cp -r` error printed but not raised), a bundle without its
# root certificate must error and be removed, not ship with exit 0.
@test
def "a re-export that comes out without a root certificate is refused and removed" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-neuron $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo
    seal --repo $a.repo --no-stamp --no-root-cid | ignore
    let a_out = bundle $born.cid --repo $a.repo --out ($tmp_dir | path join a-out)
    let b = make-neuron $tmp_dir "b"
    import $a_out --repo $b.repo | ignore
    seal --repo $b.repo --no-stamp --no-root-cid | ignore

    # Corrupt the source copy so assembly produces a certless bundle root
    rm ($b.home | path join imported $born.record.neuron $born.cid $"($born.cid).cert.json")
    let dest = $tmp_dir | path join b-out
    let err = try { bundle $born.cid --repo $b.repo --out $dest | ignore; null } catch {|e| $e.msg }
    assert ($err != null and ($err | str contains "incomplete"))
    assert not ($dest | path exists)
}
