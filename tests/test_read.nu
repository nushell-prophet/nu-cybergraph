use std/assert
use std/testing *

use ../nu-cybergraph/particle.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/convention.nu
use ../nu-cybergraph/_derive.nu [derive]
use ../nu-cybergraph/_layout.nu [particle-path]

# Same fixture CIDs as test_convention.nu, plus a second signer: aggregation is
# about telling voices apart, so a one-signer fixture could not fail.
const A = "QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV"
const B = "Qmc9pm5gQqDwJMiFTmFEuTxRhSy5Cn2yt7NZh1LrxmMhSi"
const C = "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
const S = "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"
const S2 = "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsUL2"

@before-each
def setup []: nothing -> record {
    let tmp = mktemp --directory
    {tmp: $tmp root: ($tmp | path join cybergraph)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp
}

@test
def "a plain edge reads as a plain edge, an instruction reads as its verb" [] {
    let tmp = $in.tmp
    link add $A $B --signer $S --repo $tmp
    convention update-file $B $C --signer $S --repo $tmp

    let plain = link list --repo $tmp | where cid_from == $A | first
    assert equal $plain.op null
    assert equal $plain.src null

    let instr = link list --repo $tmp | where op == "update" | first
    assert equal $instr.src {about: $B, op: "update"}
    assert equal $instr.cid_to $C
    # The verb is readable without knowing the store: the source dereferences.
    assert equal $instr.cid_from (derive {about: $B, op: "update"})
}

@test
def "touching names the position, which is what tells the two ends apart" [] {
    let tmp = $in.tmp
    link add $A $B --signer $S --repo $tmp # B is a plain endpoint
    convention update-file $B $C --signer $S --repo $tmp # B is the replaced file
    convention confirm $A $B --signer $S --repo $tmp # B is inside the edge confirmed

    let roles = link touching $B --repo $tmp | get role | sort
    assert equal $roles ["cid_from.about" "cid_to" "cid_to.cid_to"]
}

@test
def "touching reaches an operand two records deep" [] {
    let tmp = $in.tmp
    # answer: {cid_from: {about: B, op: question}, cid_to: Q, op: answer} → A
    convention answer $B "why?" "because" --signer $S --repo $tmp
    let hit = link touching $B --repo $tmp
    assert equal ($hit | length) 1
    assert equal ($hit | first | get role) "cid_from.cid_from.about"
    assert equal ($hit | first | get op) "answer"
}

@test
def "a link naming one CID twice is returned twice" [] {
    let tmp = $in.tmp
    link add $A $A --signer $S --repo $tmp
    assert equal (link touching $A --repo $tmp | get role | sort) ["cid_from" "cid_to"]
}

@test
def "tally counts links and signers per verb and position, and never their sum" [] {
    let tmp = $in.tmp
    link add $A $B --signer $S --repo $tmp # the edge
    link add $A $B --signer $S2 --repo $tmp # the same edge, another signer
    convention confirm $A $B --signer $S2 --repo $tmp # confirmation of it
    convention update-file $B $C --signer $S --repo $tmp

    let t = link tally $B --repo $tmp
    let plain = $t | where op == null and role == "cid_to" | first
    assert equal $plain.links 2
    assert equal $plain.signers 2 # two voices, not one twice
    let confirmed = $t | where op == "confirm" | first
    assert equal $confirmed.links 1
    # Repetition and confirmation stay two numbers: no row merges them, and no
    # column totals them.
    assert equal ($t | columns) [op role links signers]
}

@test
def "a published file that is not a canonical record is not an instruction" [] {
    let tmp = $in.tmp
    # A JSON object with a non-string value is not the format's record form, so
    # its fields are not operands and the edge is plain.
    let nested = particle add '{"about":{"cid":"x"},"op":"update"}' --repo $tmp
    link add $nested $C --signer $S --repo $tmp
    let plain = particle add "just text" --repo $tmp
    link add $plain $C --signer $S --repo $tmp

    assert equal (link list --repo $tmp | get op | uniq) [null]
}

@test
def "the reader refuses a store file that does not hash to its name" [] {
    let ctx = $in
    convention update-file $B $C --signer $S --repo $ctx.tmp
    let src = derive {about: $B, op: "update"}
    "tampered" | save --force --raw (particle-path $ctx.root $src)
    assert error {|| link list --repo $ctx.tmp }
}
