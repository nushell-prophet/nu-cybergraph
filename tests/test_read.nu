use std/assert
use std/testing *

use ../nu-cybergraph/particle.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/convention.nu
use ../nu-cybergraph/_derive.nu [ derive ]
use ../nu-cybergraph/_layout.nu [ particle-path ]

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
    link add $A $B --signer $S --repo $tmp --allow-missing
    convention update-file $B $C --signer $S --repo $tmp --allow-missing

    let plain = link list --repo $tmp | where cid_from == $A | first
    assert equal $plain.op null
    assert equal $plain.src null

    let instr = link list --repo $tmp | where op == "update" | first
    assert equal $instr.src {about: $B op: "update"}
    assert equal $instr.cid_to $C
    # The verb is readable without knowing the store: the source dereferences.
    assert equal $instr.cid_from (derive {about: $B op: "update"})
}

@test
def "touching names the position, which is what tells the two ends apart" [] {
    let tmp = $in.tmp
    link add $A $B --signer $S --repo $tmp --allow-missing # B is a plain endpoint
    convention update-file $B $C --signer $S --repo $tmp --allow-missing # B is the replaced file
    convention confirm $A $B --signer $S --repo $tmp --allow-missing # B is inside the edge confirmed

    let roles = link touching $B --repo $tmp | get role | sort
    assert equal $roles ["cid_from.about" "cid_to" "cid_to.cid_to"]
}

@test
def "touching reaches an operand two records deep" [] {
    let tmp = $in.tmp
    # answer: {cid_from: {about: B, op: question}, cid_to: Q, op: answer} → A
    convention answer $B "why?" "because" --signer $S --repo $tmp --allow-missing
    let hit = link touching $B --repo $tmp
    assert equal ($hit | length) 1
    assert equal ($hit | first | get role) "cid_from.cid_from.about"
    assert equal ($hit | first | get op) "answer"
}

@test
def "a link naming one CID twice is returned twice" [] {
    let tmp = $in.tmp
    link add $A $A --signer $S --repo $tmp --allow-missing
    assert equal (link touching $A --repo $tmp | get role | sort) ["cid_from" "cid_to"]
}

@test
def "tally counts links and signers per verb and position, and never their sum" [] {
    let tmp = $in.tmp
    link add $A $B --signer $S --repo $tmp --allow-missing # the edge
    link add $A $B --signer $S2 --repo $tmp --allow-missing # the same edge, another signer
    convention confirm $A $B --signer $S2 --repo $tmp --allow-missing # confirmation of it
    convention update-file $B $C --signer $S --repo $tmp --allow-missing

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
def "the rg-narrowed reading and the full scan return the same rows" [] {
    let tmp = $in.tmp
    link add $A $B --signer $S --repo $tmp --allow-missing
    convention update-file $B $C --signer $S --repo $tmp --allow-missing
    convention confirm $A $B --signer $S2 --repo $tmp --allow-missing
    convention answer $B "why?" "because" --signer $S --repo $tmp --allow-missing
    # rg only drops files that cannot contain the CID, so the two must agree.
    # This is what keeps the fast path from becoming a second implementation.
    assert equal (link touching $B --repo $tmp) (link touching $B --repo $tmp --scan)
    assert equal (link tally $B --repo $tmp) (link tally $B --repo $tmp --scan)
    # Asserted outright as well: with no rg on PATH both sides run the same
    # branch, and an equality test alone would then pin nothing.
    assert equal (link touching $B --repo $tmp --scan | get role | sort) [
        "cid_from.about"
        "cid_from.cid_from.about"
        "cid_to"
        "cid_to.cid_to"
    ]
}

# The graph's files are the ones link-files walks and store names that parse
# as an address. Anything else in those directories belongs to nobody: rg
# sees a dotfile and recurses into subdirectories, a listing does neither,
# and before both sides were filtered by the same rule the two disagreed —
# one returned a row the other did not, or raised where the other did not.
@test
def "a file that is not a graph file is ignored by both readings" [] {
    let ctx = $in
    convention update-file $B $C --signer $S --repo $ctx.tmp --allow-missing
    let expected = link touching $B --repo $ctx.tmp

    $"mentions ($B)" | save --raw ($ctx.root | path join particles .note)
    mkdir ($ctx.root | path join particles sub)
    $"mentions ($B)" | save --raw ($ctx.root | path join particles sub buried)
    "not a record" | save --raw ($ctx.root | path join $S notes.txt)

    assert equal (link touching $B --repo $ctx.tmp) $expected
    assert equal (link touching $B --repo $ctx.tmp --scan) $expected
}

@test
def "a signer is named by every link it signed" [] {
    let tmp = $in.tmp
    link add $A $B --signer $S --repo $tmp --allow-missing
    link add $A $C --signer $S --repo $tmp --allow-missing
    link add $B $C --signer $S2 --repo $tmp --allow-missing
    let signed = link touching $S --repo $tmp
    assert equal ($signed | get role | uniq) ["signer"]
    assert equal ($signed | length) 2
}

@test
def "a file that only quotes a CID states nothing about it" [] {
    let tmp = $in.tmp
    # The text search finds this file; reading it decides. A chapter naming a
    # CID in prose is not an edge, and no verification step would make it one.
    let quoting = particle add $"see ($B) for the earlier version" --repo $tmp
    link add $quoting $C --signer $S --repo $tmp --allow-missing
    assert equal (link touching $B --repo $tmp) []
}

@test
def "a published file that is not a canonical record is not an instruction" [] {
    let tmp = $in.tmp
    # A JSON object with a non-string value is not the format's record form, so
    # its fields are not operands and the edge is plain.
    let nested = particle add '{"about":{"cid":"x"},"op":"update"}' --repo $tmp
    link add $nested $C --signer $S --repo $tmp --allow-missing
    let plain = particle add "just text" --repo $tmp
    link add $plain $C --signer $S --repo $tmp --allow-missing

    assert equal (link list --repo $tmp | get op | uniq) [null]
}

@test
def "the reader refuses a store file that does not hash to its name" [] {
    let ctx = $in
    convention update-file $B $C --signer $S --repo $ctx.tmp --allow-missing
    let src = derive {about: $B op: "update"}
    "tampered" | save --force --raw (particle-path $ctx.root $src)
    assert error {|| link list --repo $ctx.tmp }
}
