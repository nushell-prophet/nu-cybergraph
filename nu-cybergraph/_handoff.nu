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

use _record.nu [CID_V0_RE RFC3339_RE]
use _receipt.nu [SHA256_RE]

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
# Why v1 and not v2 after the format bump: the pre-tag handoff carried no
# version claim at all, so nothing ever called itself v1 and no reader can
# confuse the two — validate-handoff refuses a record without the key outright.
# v1 is the first handoff format that has a name.
export const HANDOFF_SCHEMA = "cybergraph-handoff-v1"

# `schema` FIRST, so the signed bytes open with the domain tag.
export const HANDOFF_KEYS = [schema link from to receipt handed_at]

# Enforce the handoff shape: exact HANDOFF_KEYS set, the schema token byte-exact,
# CID fields (link, from, to), receipt hash-or-null, RFC 3339 handed_at.
export def validate-handoff [rec: record]: nothing -> nothing {
    let cols = $rec | columns
    if ($cols | sort) != ($HANDOFF_KEYS | sort) {
        error make {msg: $"handoff must have exactly keys ($HANDOFF_KEYS | str join ', ') — got ($cols | str join ', ')"}
    }
    # Byte-exact, like parse-root-statement: a wrong or drifted token is a
    # different format, never something to tolerate and read anyway.
    if $rec.schema != $HANDOFF_SCHEMA {
        error make {msg: $"handoff schema must be exactly ($HANDOFF_SCHEMA): ($rec.schema | to json)"}
    }
    for key in [link from to] {
        if ($rec | get $key) !~ $CID_V0_RE {
            error make {msg: $"handoff ($key) must be a base58btc CID v0: (($rec | get $key) | to json)"}
        }
    }
    if $rec.receipt != null and $rec.receipt !~ $SHA256_RE {
        error make {msg: $"handoff receipt must be null or a sha256 hex: ($rec.receipt | to json)"}
    }
    if $rec.handed_at !~ $RFC3339_RE {
        error make {msg: $"handoff handed_at is not an RFC 3339 timestamp: ($rec.handed_at | to json)"}
    }
}

# Deterministic bytes, same discipline as records and receipts: keys in
# HANDOFF_KEYS order, compact JSON, one trailing newline.
export def handoff-bytes [rec: record]: nothing -> binary {
    validate-handoff $rec
    ($rec | select ...$HANDOFF_KEYS | to json --raw) + "\n" | into binary
}

# Read a handoff file and validate its shape — authenticity is the detached
# signature beside it, checked by verification, not here.
export def read-handoff [file: path]: nothing -> record {
    let rec = open --raw $file | from json
    validate-handoff $rec
    $rec
}
