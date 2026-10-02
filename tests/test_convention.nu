use std/assert
use std/testing *

use ../nu-cybergraph/convention.nu
use ../nu-cybergraph/particle.nu
use ../nu-cybergraph/_derive.nu [ derive record-bytes ]
use ../nu-cybergraph/_layout.nu [ particles-dir particle-path ]
use ../nu-cybergraph/_deps/cid-v0.nu [ cid-v0 ]

# File/signer CIDs of the bj003 smoke run; S is the record golden's signer.
const A = "QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV"
const B = "Qmc9pm5gQqDwJMiFTmFEuTxRhSy5Cn2yt7NZh1LrxmMhSi"
const C = "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
const S = "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"

# --- The byte-format pin -----------------------------------------------------
# A derived CID is the CID v0 of a canonical record: compact JSON, keys in
# alphabetical order, string values only, exactly one trailing "\n" — the
# record form of bj002's appendix. Reproduce any of these with
# `printf '<record>\n' | ipfs add --only-hash --cid-version=0`. Changing the
# serialization breaks every derived CID — this test is the pin, same role as
# test_record.nu's GOLDEN_CID.
const CONFIRM_EDGE = "QmcqM2jDzeLmPQYRVtMvJypmo8NS7xGh2HNgVLFepL5QKQ" # {"op":"confirm_edge"}
const CONFIRM_LINK = "QmTJipuBLbsHCgRRe9BrGeGbZFFNoYFwzbiEQgGzDpaHNj" # {"op":"confirm_link"}
const DENY_EDGE = "QmXegbm1GjDayyetHt87fvAicrE42SQqfd7G4Gwnr1SSr5" # {"op":"deny_edge"}
const DENY_LINK = "QmZ27sgjKKC2HDS6o7Kk1L8PCANGxArGRxgNcay9ENC2jP" # {"op":"deny_link"}
const AGREE_PARTICLE = "QmUjmrKj4nYsbKg27ZSepjWFEyt54B5rMD6V4Mp4pUH3sA" # {"op":"agree_particle"}
const DISAGREE_PARTICLE = "QmQjBGThDKWcsBHZsCDtUL2GwB5FWoKXJM6Sfsgo3EtshK" # {"op":"disagree_particle"}
const EDGE_AB = "QmawrHuBDdcSRCPumzsKfsMi5FJne8xai9WNPAdr3NmLBV" # {"cid_from":A,"cid_to":B} — the edge address
const CYBERLINK_ABS = "Qme4L2P7QwNoijw6HzYVrqrrtk99oj1XvJHvAb9yobHVLe" # {"cid_from":A,"cid_to":B,"signer":S}

# The same order `link add` keeps, one level up: `address` publishes every
# record it mints, so a convention run in a repo with no signer identity must
# leave nothing behind.
@test
def "a convention publishes nothing when the repo has no signer identity" [] {
    let tmp = $in.tmp

    assert error {|| convention agree-particle "bostrom" --repo $tmp }
    # The confirm and deny verbs reach the store before `edge` does — they
    # publish their own target through `_publish.nu` — so they resolve the
    # signer themselves, or a refused act leaves its target record behind. One
    # verb of each shape, since all four publish the same way.
    assert error {|| convention confirm-edge $A $B --repo $tmp --allow-missing }
    assert error {|| convention deny-link $A $B $S --repo $tmp --allow-missing }
    assert not ((particles-dir ($tmp | path join cybergraph)) | path exists)
}

@test
def "derive golden CIDs pin the record canon" [] {
    assert equal (derive {op: "confirm_edge"}) $CONFIRM_EDGE
    assert equal (derive {op: "confirm_link"}) $CONFIRM_LINK
    assert equal (derive {op: "deny_edge"}) $DENY_EDGE
    assert equal (derive {op: "deny_link"}) $DENY_LINK
    assert equal (derive {op: "agree_particle"}) $AGREE_PARTICLE
    assert equal (derive {op: "disagree_particle"}) $DISAGREE_PARTICLE
    assert equal (derive {cid_from: $A cid_to: $B}) $EDGE_AB
    assert equal (derive {cid_from: $A cid_to: $B signer: $S}) $CYBERLINK_ABS
}

@test
def "record-bytes emits alphabetical keys as compact JSON with one trailing newline" [] {
    assert equal (record-bytes {op: "deny_edge"} | decode) "{\"op\":\"deny_edge\"}\n"
    # Keys given out of canonical order come out alphabetical.
    assert equal (record-bytes {op: "quote_particle" about: $A} | decode) $"{\"about\":\"($A)\",\"op\":\"quote_particle\"}\n"
}

@test
def "record-bytes refuses non-string values" [] {
    assert error { record-bytes {about: {cid_from: $A cid_to: $B} op: "answer_edge"} }
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

# The subject signer of `confirm-link A B S` is an identity, not a stored particle.
# `confirm-link` and `particle add-link` both come through
# `_publish.nu`, so the signer follows `resolve-signer` here exactly as it
# does everywhere else.
@test
def "confirming a cyberlink does not demand the subject signer in the store" [] {
    let tmp = $in.tmp
    let r = convention confirm-link $A $B $S --repo $tmp --signer $S --allow-missing

    assert equal $r.record.cid_to $CYBERLINK_ABS
    # And with both endpoints local, no flag at all is needed — the signer is
    # not what the check is about.
    let a = particle add "cyber" --repo $tmp
    let b = particle add "prophet" --repo $tmp
    let r2 = convention confirm-link $a $b $S --repo $tmp --signer $S

    assert equal $r2.record.cid_to (derive {cid_from: $a cid_to: $b signer: $S})
}

# One construction site: the address a convention targets is the address the
# public publisher returns, byte-identical, or the two have drifted again.
@test
def "the convention target and the public publisher agree" [] {
    let tmp = $in.tmp
    let a = particle add "cyber" --repo $tmp
    let b = particle add "prophet" --repo $tmp
    let confirmed = convention confirm-link $a $b $S --repo $tmp --signer $S

    assert equal $confirmed.record.cid_to (particle add-link $a $b $S --repo $tmp)
    let plain = convention confirm-edge $a $b --repo $tmp --signer $S

    assert equal $plain.record.cid_to (particle add-edge $a $b --repo $tmp)
}

@test
def "repeat publishes the plain edge with no instruction source" [] {
    let r = convention repeat $A $B --repo $in.tmp --signer $S --allow-missing | get record

    assert equal $r.cid_from $A
    assert equal $r.cid_to $B
}

@test
def "repeat is idempotent and replaying the same act returns the same record" [] {
    let tmp = $in.tmp
    let first = convention repeat $A $B --repo $tmp --signer $S --allow-missing
    let again = convention repeat $A $B --repo $tmp --signer $S --allow-missing

    assert equal $again $first
}

@test
def "confirm-edge targets the edge address and confirm-link the cyberlink CID" [] {
    let tmp = $in.tmp
    let edge = convention confirm-edge $A $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $edge.cid_from $CONFIRM_EDGE
    assert equal $edge.cid_to $EDGE_AB

    let link = convention confirm-link $A $B $S --repo $tmp --signer $S --allow-missing | get record

    assert equal $link.cid_from $CONFIRM_LINK
    assert equal $link.cid_to $CYBERLINK_ABS

    # Two subjects, two fixed sources: the op word alone tells a reader which
    # act it is holding, without parsing the target record.
    assert not equal $edge.cid_from $link.cid_from
}

@test
def "deny-edge targets the edge address and deny-link the cyberlink CID" [] {
    let tmp = $in.tmp
    let edge = convention deny-edge $A $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $edge.cid_from $DENY_EDGE
    assert equal $edge.cid_to $EDGE_AB

    let link = convention deny-link $A $B $S --repo $tmp --signer $S --allow-missing | get record

    assert equal $link.cid_from $DENY_LINK
    assert equal $link.cid_to $CYBERLINK_ABS

    assert not equal $edge.cid_from $link.cid_from
}

@test
def "update-edge reissues from the record naming the address of the edge" [] {
    let r = convention update-edge $A $B $C --repo $in.tmp --signer $S --allow-missing | get record

    assert equal $r.cid_from (derive {about: $EDGE_AB op: "update_edge"})
    assert equal $r.cid_to $C
}

@test
def "update-particle states the same act about a particle at a distinct address" [] {
    let tmp = $in.tmp
    let r = convention update-particle $B $C --repo $tmp --signer $S --allow-missing | get record

    assert equal $r.cid_from (derive {about: $B op: "update_particle"})
    assert equal $r.cid_to $C

    # Its own op word, so the two acts are apart even where the subject is one
    # CID: the record shape is the same, and only the word differs.
    assert not equal $r.cid_from (derive {about: $B op: "update_edge"})

    # The source is the version being replaced, so a reader who holds B can
    # compute one hash and ask what replaced it. A chain is updates of updates.
    let next = convention update-particle $C $A --repo $tmp --signer $S --allow-missing | get record

    assert equal $next.cid_from (derive {about: $C op: "update_particle"})
}

@test
def "operand-embedding conventions put the operand in the source" [] {
    let tmp = $in.tmp
    let q = convention quote-particle $A $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $q.cid_from (derive {about: $A op: "quote_particle"})
    assert equal $q.cid_to $B

    let pro = convention pro $C $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $pro.cid_from (derive {about: $C op: "pro"})
    assert equal $pro.cid_to $B

    let con = convention con $C $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $con.cid_from (derive {about: $C op: "con"})

    let qn = convention question $A $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $qn.cid_from (derive {about: $A op: "question"})

    let au = convention author-particle $A $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $au.cid_from (derive {about: $A op: "author_particle"})

    let sm = convention same $A $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $sm.cid_from (derive {about: $A op: "same"})
    assert equal $sm.cid_to $B

    # Directed, and the source is the original: a reader holding the text asks
    # which translations exist, and the pair records which language came first.
    let tr = convention translation-particle $A $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $tr.cid_from (derive {about: $A op: "translation_particle"})
    assert equal $tr.cid_to $B
    assert not equal $tr.cid_from (derive {about: $B op: "translation_particle"})
}

# --literal plumbing through address/edge to resolve-particle — checked once
# on `pro`, since every verb's content operand routes through the same
# `address` call (see convention.nu's `edge`/`address`).
@test
def "a text operand opens a path argument and --literal forces literal" [] {
    let tmp = $in.tmp
    let file = $tmp | path join "argument.md"

    "the evidence" | save --raw $file
    let opened = convention pro $C $file --repo $tmp --signer $S --allow-missing | get record

    assert equal $opened.cid_to ("the evidence" | into binary | cid-v0)

    let literal = convention pro $C $file --repo $tmp --signer $S --allow-missing --literal | get record

    assert equal $literal.cid_to ($file | into binary | cid-v0)
}

@test
def "agree and disagree use the fixed source and target the file" [] {
    let tmp = $in.tmp
    let a = convention agree-particle $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $a.cid_from $AGREE_PARTICLE
    assert equal $a.cid_to $B
    let d = convention disagree-particle $B --repo $tmp --signer $S --allow-missing | get record

    assert equal $d.cid_from $DISAGREE_PARTICLE
    assert equal $d.cid_to $B
}

@test
def "answer attaches to the question in context and not the bare question" [] {
    let r = convention answer-edge $A $B $C --repo $in.tmp --signer $S --allow-missing | get record
    let q_src = derive {about: $A op: "question"}

    assert equal $r.cid_from (derive {about: (derive {cid_from: $q_src cid_to: $B}) op: "answer_edge"})
    assert equal $r.cid_to $C
}

@test
def "claimed-at publishes the timestamp as a file and edges to it" [] {
    let t = "2026-07-16T00:00:00+00:00"
    let r = convention claimed-at $A $t --repo $in.tmp --signer $S --allow-missing | get record

    assert equal $r.cid_from (derive {about: $A op: "claimed_at"})
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

    convention deny-edge $A $B --repo $tmp --signer $S --allow-missing | ignore
    convention answer-edge $A $B $C --repo $tmp --signer $S --allow-missing | ignore

    let particles = ls (particles-dir ($tmp | path join cybergraph))
    # Filename == CID v0 of the file's own bytes, for every file written.
    let misaddressed = $particles
        | where ($it.name | path basename) != (open --raw $it.name | into binary | cid-v0)

    assert equal ($misaddressed | length) 0

    # The record is its own preimage: dereferencing the source of a deny edge
    # yields the canonical record bytes.
    assert equal (open --raw (particle-path ($tmp | path join cybergraph) $DENY_EDGE)) "{\"op\":\"deny_edge\"}\n"
    # deny-edge publishes the address record it targets.
    assert ((particle-path ($tmp | path join cybergraph) $EDGE_AB) | path exists) $"missing address record ($EDGE_AB)"
    # answer publishes the whole chain: the question record, the address of the
    # question edge, and the answer record.
    let q_src = derive {about: $A op: "question"}
    let q_edge = derive {cid_from: $q_src cid_to: $B}

    for cid in [$q_src $q_edge (derive {about: $q_edge op: "answer_edge"})] {
        assert ((particle-path ($tmp | path join cybergraph) $cid) | path exists) $"missing record ($cid)"
    }
}

# Alone, with no deny-edge in the same repo to publish the edge address first.
@test
def "update-edge publishes the address of the edge and its update record" [] {
    let tmp = $in.tmp

    convention update-edge $A $B $C --repo $tmp --signer $S --allow-missing | ignore

    for cid in [$EDGE_AB (derive {about: $EDGE_AB op: "update_edge"})] {
        assert ((particle-path ($tmp | path join cybergraph) $cid) | path exists) $"missing record ($cid)"
    }
}
