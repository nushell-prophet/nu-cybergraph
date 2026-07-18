use std/assert
use std/testing *

use ../nu-cybergraph/convention.nu
use ../nu-cybergraph/_derive.nu [derive preimage]
use ../nu-cybergraph/_layout.nu [particles-dir particle-path]
use ../nu-cybergraph/_deps/cid-v0.nu [cid-v0]

# Same particle/neuron CIDs as the record golden and the bj003 smoke run.
const A = "QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV"
const B = "Qmc9pm5gQqDwJMiFTmFEuTxRhSy5Cn2yt7NZh1LrxmMhSi"
const C = "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
const N = "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"

# --- The byte-format pin -----------------------------------------------------
# hash() = CID v0 of the argument string joined with commas, NO trailing
# newline. Reproduce any of these with `printf '<preimage>' | ipfs add
# --only-hash --cid-version=0`; the empty-arg cases were cross-checked against
# ipfs. Changing the join or the byte encoding breaks every derived CID — this
# test is the pin, same role as test_record.nu's GOLDEN_CID.
const DENY = "QmZPK9aVYGNvbqp3vwEkANcqMY1eTkJHjE1VC9iSfU9SRL"
const AGREE = "QmTqtCbUfyZE8PgaFCHRpt3EJgKYvcVjVBTofuiEAa893g"
const DISAGREE = "QmQf6giQaTXvbyboXYBXaQLzrgtpXQxBN2hNH4rLjjqW49"
const EDGE_AB = "QmeNVaUs7Xiog4yJsDrtD8QcDVFXPDc79kp96ZAqyB7kQK" # hash(A, B) — the edge address
const CYBERLINK_ABN = "QmbvkzyS1eHxUoSJFaYJpvKjCpSiG2io8xogmenaC9zah6" # hash(A, B, N)

@test
def "derive golden CIDs pin the byte format" [] {
    assert equal (derive "deny") $DENY
    assert equal (derive "agree") $AGREE
    assert equal (derive "disagree") $DISAGREE
    assert equal (derive $A $B) $EDGE_AB
    assert equal (derive $A $B $N) $CYBERLINK_ABN
}

@test
def "preimage joins arguments with commas, nothing else" [] {
    assert equal (preimage "deny") "deny"
    assert equal (preimage $A $B) $"($A),($B)"
    assert equal (preimage "update" (derive $A $B)) $"update,($EDGE_AB)"
}

# --- Each convention shapes the right edge -----------------------------------
# Written to a plain directory: an existing --repo path needs no git/ssh/init
# (link add mkdirs links/). Author and time are fixed so the run is offline and
# deterministic; the assertions are on cid_from/cid_to — the shape of the edge,
# independent of who signs it.
@before-each
def setup []: nothing -> record {
    {tmp: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp
}

# Fixed author + time so the run is offline and deterministic; the assertions
# are on cid_from/cid_to — the shape of the edge, not who signs it.
const T = "2026-07-18T00:00:00+00:00"

@test
def "confirm repeats the plain edge, no instruction source" [] {
    let r = convention confirm $A $B --repo $in.tmp --neuron $N --claimed-at $T | get record
    assert equal $r.cid_from $A
    assert equal $r.cid_to $B
}

@test
def "deny targets the edge address, or the cyberlink CID with a neuron" [] {
    let tmp = $in.tmp
    let edge = convention deny $A $B --repo $tmp --neuron $N --claimed-at $T | get record
    assert equal $edge.cid_from $DENY
    assert equal $edge.cid_to $EDGE_AB

    let link = convention deny $A $B $N --repo $tmp --neuron $N --claimed-at $T | get record
    assert equal $link.cid_from $DENY
    assert equal $link.cid_to $CYBERLINK_ABN
}

@test
def "update reissues from hash of update and the edge address" [] {
    let r = convention update $A $B $C --repo $in.tmp --neuron $N --claimed-at $T | get record
    assert equal $r.cid_from (derive "update" (derive $A $B))
    assert equal $r.cid_to $C
}

@test
def "operand-embedding conventions put the operand in the source" [] {
    let tmp = $in.tmp
    let q = convention quote $A $B --repo $tmp --neuron $N --claimed-at $T | get record
    assert equal $q.cid_from (derive "quote" $A)
    assert equal $q.cid_to $B

    let pro = convention pro $C $B --repo $tmp --neuron $N --claimed-at $T | get record
    assert equal $pro.cid_from (derive "pro" $C)
    assert equal $pro.cid_to $B

    let con = convention con $C $B --repo $tmp --neuron $N --claimed-at $T | get record
    assert equal $con.cid_from (derive "con" $C)

    let qn = convention question $A $B --repo $tmp --neuron $N --claimed-at $T | get record
    assert equal $qn.cid_from (derive "question" $A)

    let au = convention author $A $B --repo $tmp --neuron $N --claimed-at $T | get record
    assert equal $au.cid_from (derive "author" $A)

    let sm = convention same $A $B --repo $tmp --neuron $N --claimed-at $T | get record
    assert equal $sm.cid_from (derive "same" $A)
    assert equal $sm.cid_to $B
}

@test
def "agree and disagree use the fixed source, target is the content" [] {
    let tmp = $in.tmp
    let a = convention agree $B --repo $tmp --neuron $N --claimed-at $T | get record
    assert equal $a.cid_from $AGREE
    assert equal $a.cid_to $B
    let d = convention disagree $B --repo $tmp --neuron $N --claimed-at $T | get record
    assert equal $d.cid_from $DISAGREE
    assert equal $d.cid_to $B
}

@test
def "answer attaches to the question-in-context, not the bare question" [] {
    let r = convention answer $A $B $C --repo $in.tmp --neuron $N --claimed-at $T | get record
    let q_edge = derive (derive "question" $A) $B
    assert equal $r.cid_from (derive "answer" $q_edge)
    assert equal $r.cid_to $C
}

# --- Preimages are published and self-addressed ------------------------------
@test
def "every convention publishes self-addressed preimage particles" [] {
    let tmp = $in.tmp
    convention deny $A $B --repo $tmp --neuron $N --claimed-at $T | ignore
    convention answer $A $B $C --repo $tmp --neuron $N --claimed-at $T | ignore

    let particles = ls (particles-dir ($tmp | path join cybergraph))
    # Filename == CID v0 of the file's own bytes, for every particle written.
    let misaddressed = $particles | where {|p|
        ($p.name | path basename) != (open --raw $p.name | into binary | cid-v0)
    }
    assert equal ($misaddressed | length) 0

    # The instruction source is dereferenceable: hash("deny") holds "deny".
    assert equal (open --raw (particle-path ($tmp | path join cybergraph) $DENY)) "deny"
    # answer publishes the whole chain: question source, question edge, answer source.
    let q_edge = derive (derive "question" $A) $B
    for cid in [(derive "question" $A) $q_edge (derive "answer" $q_edge)] {
        assert ((particle-path ($tmp | path join cybergraph) $cid) | path exists) $"missing preimage ($cid)"
    }
}
