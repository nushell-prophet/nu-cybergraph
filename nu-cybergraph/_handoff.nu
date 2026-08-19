# The handoff — the sender's signed claim "I handed this link's bundle to
# signer `to`". Custody proves holding; the handoff adds DIRECTION as a
# signed statement instead of an inference from who held what. It remains a
# claim of sending, not a proof of delivery.
#
# A handoff cannot ride a seal: it is written at export time and the bundle
# leaves immediately, before any later seal could catalogue it. So it is the
# one artifact signed directly (detached ssh-keygen signature beside the
# file) rather than through a merkle root.
#
# `receipt` pins the sha256 of the sender's receipt file (null when the
# sender is the author, who has no receipt), tying the claim to the exact
# chain state handed over. The RECIPIENT's receipt then hashes the handoff
# file back (its `handoff` field), pulling the claim into the sealed chain —
# stripping a handoff breaks the next receipt, so it cannot be silently
# removed once the recipient sealed.

use _derive.nu [ ordered-bytes ]
use _validate.nu [ assert-keys assert-cids assert-timestamp assert-hash-or-null ]

# Domain separation lives in the SIGNED BYTES, not in the signature namespace.
# nu-multiproof used to take a `--namespace` on sign/verify; the value was
# interpolated raw into the allowed_signers line beside the principal, so a
# crafted namespace injected `cert-authority` and rendered every registered key
# trusted for anything. The flag is gone and every signature this toolchain
# makes is under the generic `file` namespace — which is exactly why the bytes
# must say what they are. Same shape as nu-multiproof's `root-statement`
# ("multiproof-merkle-v1 <hex>"), in this repo's JSON idiom: a leading schema
# token, so a handoff signature cannot be replayed as any other artifact this
# key signs, and vice versa.
#
# v1 was the first handoff format that had a name at all — the pre-tag one
# carried no version claim, so nothing ever called itself v0. v2 is the first
# real bump: v1 named its act by the cyberlink's derived CID, v2 states the
# act's three components (below). The token is what tells them apart, which is
# the job it was added for.
export const HANDOFF_SCHEMA = "cybergraph-handoff-v2"

# `schema` FIRST, so the signed bytes open with the domain tag. Then the act
# spelled out — `cid_from`, `cid_to`, `signer` — the same three components a
# receipt states, for the same reason: read on its own, the file says which
# act it moves, with no store to dereference a derived CID in. Symmetry is
# the rest of the reason — one act described two ways across the two custody
# artifacts was a needless second notation.
#
# `signer` is the act's AUTHOR and does not move; `from` and `to` are the
# holders this transfer is between. For the author's own handoff they
# coincide, and that is a fact about the transfer, not a duplicated field.
export const HANDOFF_KEYS = [schema cid_from cid_to signer from to receipt handed_at]

# Enforce the handoff shape: exact HANDOFF_KEYS set, the schema token byte-exact,
# CID fields (the act's three, plus from and to), receipt hash-or-null,
# RFC 3339 handed_at.
export def validate-handoff [rec: record]: nothing -> nothing {
    assert-keys $rec $HANDOFF_KEYS "handoff"
    # Byte-exact, like parse-root-statement: a wrong or drifted token is a
    # different format, never something to tolerate and read anyway.
    if $rec.schema != $HANDOFF_SCHEMA {
        error make {msg: $"handoff schema must be exactly ($HANDOFF_SCHEMA): ($rec.schema | to json)"}
    }
    assert-cids $rec [cid_from cid_to signer from to] "handoff"
    assert-hash-or-null $rec receipt "handoff"
    assert-timestamp $rec handed_at "handoff"
}

# Deterministic bytes, same discipline as records and receipts: keys in
# HANDOFF_KEYS order, compact JSON, one trailing newline.
export def handoff-bytes [rec: record]: nothing -> binary {
    validate-handoff $rec
    ordered-bytes $rec $HANDOFF_KEYS
}

# Read a handoff file and validate its shape — authenticity is the detached
# signature beside it, checked by verification, not here.
export def read-handoff [file: path]: nothing -> record {
    let rec = open --raw $file | from json
    validate-handoff $rec
    $rec
}
