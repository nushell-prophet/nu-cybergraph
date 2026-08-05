use std/assert
use std/testing *

use ../nu-cybergraph/convention.nu
use ../nu-cybergraph/_derive.nu [derive record-bytes]
use ../nu-cybergraph/_layout.nu [particles-dir particle-path]
use ../nu-cybergraph/_deps/cid-v0.nu [cid-v0]

# File/signer CIDs of the bj003 smoke run; S is the record golden's signer.
const A = "QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV"
const B = "Qmc9pm5gQqDwJMiFTmFEuTxRhSy5Cn2yt7NZh1LrxmMhSi"
const C = "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
const S = "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"

# --- The byte-format pin -----------------------------------------------------
# A derived CID is the CID v0 of a canonical record: compact JSON, keys in
# alphabetical order, string values only, exactly one trailing "\n" — this
# repo's record form of bj002's appendix. Reproduce any of these with
# `printf '<record>\n' | ipfs add --only-hash --cid-version=0`. Changing the
# serialization breaks every derived CID — this test is the pin, same role as
# test_record.nu's GOLDEN_CID.
const CONFIRM = "QmcLFo8UMWWuUP7ruztAW5C1zPwmF7GTZs8X6Lig4pXkBh" # {"op":"confirm"}
const DENY = "QmU8kL28M7yecZ5iPGJZ3e89fytWFzLszU3QtKRj5hV2kK" # {"op":"deny"}
const AGREE = "QmTswdDR4inURY4GeWGvmL9S8xrDZjfiGEyeUUZzUNRNYk" # {"op":"agree"}
const DISAGREE = "QmbQUXxqMrFA6zGYmgjvbFKyywS7Gcbb3afb3wqG6s7r6J" # {"op":"disagree"}
const EDGE_AB = "QmawrHuBDdcSRCPumzsKfsMi5FJne8xai9WNPAdr3NmLBV" # {"cid_from":A,"cid_to":B} — the edge address
const CYBERLINK_ABS = "Qme4L2P7QwNoijw6HzYVrqrrtk99oj1XvJHvAb9yobHVLe" # {"cid_from":A,"cid_to":B,"signer":S}

# The same order `link add` keeps, one level up: `address` publishes every
# record it mints, so a convention run in a repo with no signer identity must
# leave nothing behind.
@test
def "a convention publishes nothing when the repo has no signer identity" [] {
    let tmp = $in.tmp
    assert error {|| convention agree "bostrom" --repo $tmp }
    assert not ((particles-dir ($tmp | path join cybergraph)) | path exists)
}

@test
def "derive golden CIDs pin the record canon" [] {
    assert equal (derive {op: "confirm"}) $CONFIRM
    assert equal (derive {op: "deny"}) $DENY
    assert equal (derive {op: "agree"}) $AGREE
    assert equal (derive {op: "disagree"}) $DISAGREE
    assert equal (derive {cid_from: $A, cid_to: $B}) $EDGE_AB
    assert equal (derive {cid_from: $A, cid_to: $B, signer: $S}) $CYBERLINK_ABS
}

@test
def "record-bytes emits alphabetical keys, compact JSON, one trailing newline" [] {
    assert equal (record-bytes {op: "deny"} | decode) "{\"op\":\"deny\"}\n"
    # Keys given out of canonical order come out alphabetical.
    assert equal (record-bytes {op: "quote", about: $A} | decode) $"{\"about\":\"($A)\",\"op\":\"quote\"}\n"
}

@test
def "record-bytes refuses non-string values" [] {
    assert error { record-bytes {cid_to: $B, cid_from: {about: $A, op: "question"}, op: "answer"} }
}

# --- Each convention shapes the right edge -----------------------------------
# Written to a plain directory: an existing --repo path needs no git/ssh/init
# (link add mkdirs links/). The signer is fixed so the run is offline and
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

@test
def "repeat publishes the plain edge, no instruction source" [] {
    let r = convention repeat $A $B --repo $in.tmp --signer $S --allow-missing | get record
    assert equal $r.cid_from $A
    assert equal $r.cid_to $B
}

@test
def "repeat is idempotent — replaying the same act returns the same record" [] {
    let tmp = $in.tmp
    let first = convention repeat $A $B --repo $tmp --signer $S --allow-missing
    let again = convention repeat $A $B --repo $tmp --signer $S --allow-missing
    assert equal $again $first
}

@test
def "confirm targets the edge address, or the cyberlink CID with a signer" [] {
    let tmp = $in.tmp
    let edge = convention confirm $A $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $edge.cid_from $CONFIRM
    assert equal $edge.cid_to $EDGE_AB

    let link = convention confirm $A $B $S --repo $tmp --signer $S --allow-missing | get record
    assert equal $link.cid_from $CONFIRM
    assert equal $link.cid_to $CYBERLINK_ABS
}

@test
def "deny targets the edge address, or the cyberlink CID with a signer" [] {
    let tmp = $in.tmp
    let edge = convention deny $A $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $edge.cid_from $DENY
    assert equal $edge.cid_to $EDGE_AB

    let link = convention deny $A $B $S --repo $tmp --signer $S --allow-missing | get record
    assert equal $link.cid_from $DENY
    assert equal $link.cid_to $CYBERLINK_ABS
}

@test
def "update reissues from the record embedding the fields of the edge" [] {
    let r = convention update $A $B $C --repo $in.tmp --signer $S --allow-missing | get record
    assert equal $r.cid_from (derive {cid_from: $A, cid_to: $B, op: "update"})
    assert equal $r.cid_to $C
}

@test
def "update-file states the same act about a file, at a distinct address" [] {
    let tmp = $in.tmp
    let r = convention update-file $B $C --repo $tmp --signer $S --allow-missing | get record
    assert equal $r.cid_from (derive {about: $B, op: "update"})
    assert equal $r.cid_to $C

    # Same op word, different arity — the record shape keeps the two addresses
    # apart, which is what lets one verb family cover edges and files.
    assert not equal $r.cid_from (derive {cid_from: $A, cid_to: $B, op: "update"})

    # The source is the version being replaced, so a reader who holds B can
    # compute one hash and ask what replaced it. A chain is updates of updates.
    let next = convention update-file $C $A --repo $tmp --signer $S --allow-missing | get record
    assert equal $next.cid_from (derive {about: $C, op: "update"})
}

@test
def "operand-embedding conventions put the operand in the source" [] {
    let tmp = $in.tmp
    let q = convention quote $A $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $q.cid_from (derive {about: $A, op: "quote"})
    assert equal $q.cid_to $B

    let pro = convention pro $C $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $pro.cid_from (derive {about: $C, op: "pro"})
    assert equal $pro.cid_to $B

    let con = convention con $C $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $con.cid_from (derive {about: $C, op: "con"})

    let qn = convention question $A $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $qn.cid_from (derive {about: $A, op: "question"})

    let au = convention author $A $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $au.cid_from (derive {about: $A, op: "author"})

    let sm = convention same $A $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $sm.cid_from (derive {about: $A, op: "same"})
    assert equal $sm.cid_to $B

    # Directed, and the source is the original: a reader holding the text asks
    # which translations exist, and the pair records which language came first.
    let tr = convention translation $A $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $tr.cid_from (derive {about: $A, op: "translation"})
    assert equal $tr.cid_to $B
    assert not equal $tr.cid_from (derive {about: $B, op: "translation"})
}

# --literal plumbing through address/edge to resolve-particle — checked once
# on `pro`, since every verb's content operand routes through the same
# `address` call (see convention.nu's `edge`/`address`).
@test
def "a text operand opens a path argument, --literal forces literal" [] {
    let tmp = $in.tmp
    let file = $tmp | path join "argument.md"
    "the evidence" | save --raw $file
    let opened = convention pro $C $file --repo $tmp --signer $S --allow-missing | get record
    assert equal $opened.cid_to ("the evidence" | into binary | cid-v0)

    let literal = convention pro $C $file --repo $tmp --signer $S --allow-missing --literal | get record
    assert equal $literal.cid_to ($file | into binary | cid-v0)
}

@test
def "agree and disagree use the fixed source, target is the file" [] {
    let tmp = $in.tmp
    let a = convention agree $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $a.cid_from $AGREE
    assert equal $a.cid_to $B
    let d = convention disagree $B --repo $tmp --signer $S --allow-missing | get record
    assert equal $d.cid_from $DISAGREE
    assert equal $d.cid_to $B
}

@test
def "answer attaches to the question-in-context, not the bare question" [] {
    let r = convention answer $A $B $C --repo $in.tmp --signer $S --allow-missing | get record
    let q_src = derive {about: $A, op: "question"}
    assert equal $r.cid_from (derive {cid_from: $q_src, cid_to: $B, op: "answer"})
    assert equal $r.cid_to $C
}

@test
def "claimed-at publishes the timestamp as a file and edges to it" [] {
    let t = "2026-07-16T00:00:00+00:00"
    let r = convention claimed-at $A $t --repo $in.tmp --signer $S --allow-missing | get record
    assert equal $r.cid_from (derive {about: $A, op: "claimed_at"})
    assert equal $r.cid_to ($t | into binary | cid-v0)
    assert equal (open --raw (particle-path ($in.tmp | path join cybergraph) $r.cid_to)) $t
}

@test
def "claimed-at refuses a non-RFC-3339 or impossible time" [] {
    let tmp = $in.tmp
    assert error {|| convention claimed-at $A "yesterday-ish" --repo $tmp --signer $S }
    # Parseable but not RFC 3339 — the shape is pinned, not just parseability
    assert error {|| convention claimed-at $A "2026-07-16" --repo $tmp --signer $S }
    # RFC 3339 shape but impossible date
    assert error {|| convention claimed-at $A "2026-13-01T00:00:00+00:00" --repo $tmp --signer $S }
}

# --- Records are published as self-addressed files -----------------------
@test
def "every convention publishes its records as self-addressed files" [] {
    let tmp = $in.tmp
    convention deny $A $B --repo $tmp --signer $S --allow-missing | ignore
    convention answer $A $B $C --repo $tmp --signer $S --allow-missing | ignore

    let particles = ls (particles-dir ($tmp | path join cybergraph))
    # Filename == CID v0 of the file's own bytes, for every file written.
    let misaddressed = $particles
        | where ($it.name | path basename) != (open --raw $it.name | into binary | cid-v0)
    assert equal ($misaddressed | length) 0

    # The record is its own preimage: dereferencing the source of a deny edge
    # yields the canonical record bytes.
    assert equal (open --raw (particle-path ($tmp | path join cybergraph) $DENY)) "{\"op\":\"deny\"}\n"
    # deny publishes the address record it targets.
    assert ((particle-path ($tmp | path join cybergraph) $EDGE_AB) | path exists) $"missing address record ($EDGE_AB)"
    # answer publishes the whole chain: the question record and the answer record.
    let q_src = derive {about: $A, op: "question"}
    for cid in [$q_src (derive {cid_from: $q_src, cid_to: $B, op: "answer"})] {
        assert ((particle-path ($tmp | path join cybergraph) $cid) | path exists) $"missing record ($cid)"
    }
}
