# The custody receipt — a custodian's statement "I received this link's
# bundle", written by import OUTSIDE the read-only imported/ copy, catalogued
# by the custodian's next seal, proven and frozen like a birth certificate,
# and shipped as a custody layer on re-export.
#
# Two commitments make a dissemination path provable in order:
# - `files`: path+sha256 manifest of the birth-bundle files as received —
#   the exact bytes, so a later mutation of any birth file breaks the layer.
# - `prev`: sha256 of the PREVIOUS custody layer's receipt file (null for the
#   first custodian). Each receipt commits to the one before it, so the chain
#   proves order transitively while every receipt stays constant-size —
#   re-listing all prior layers would grow the chain quadratically.

use _deps/cid-v0.nu [cid-v0]
use _record.nu [CID_V0_RE RFC3339_RE]
use _layout.nu [CUSTODY_DIR custody-dir]

export const RECEIPT_KEYS = [link neuron custodian received_at files prev handoff]

# Exported for _handoff.nu — same hash-field discipline.
export const SHA256_RE = '^[0-9a-f]{64}$'

# Enforce the receipt shape: exact RECEIPT_KEYS set, CID fields, RFC 3339
# received_at, non-empty files manifest, hash-or-null chain fields (prev, handoff).
export def validate-receipt [rec: record]: nothing -> nothing {
    let cols = $rec | columns
    if ($cols | sort) != ($RECEIPT_KEYS | sort) {
        error make {msg: $"receipt must have exactly keys ($RECEIPT_KEYS | str join ', ') — got ($cols | str join ', ')"}
    }
    for key in [link neuron custodian] {
        if ($rec | get $key) !~ $CID_V0_RE {
            error make {msg: $"receipt ($key) must be a base58btc CID v0: (($rec | get $key) | to json)"}
        }
    }
    if $rec.received_at !~ $RFC3339_RE {
        error make {msg: $"receipt received_at is not an RFC 3339 timestamp: ($rec.received_at | to json)"}
    }
    if ($rec.files | is-empty) {
        error make {msg: "receipt files manifest is empty"}
    }
    for f in $rec.files {
        if ($f | columns | sort) != [path sha256] or $f.sha256 !~ $SHA256_RE {
            error make {msg: $"malformed receipt files entry: ($f | to json --raw)"}
        }
    }
    if $rec.prev != null and $rec.prev !~ $SHA256_RE {
        error make {msg: $"receipt prev must be null or a sha256 hex: ($rec.prev | to json)"}
    }
    # `handoff`: sha256 of the handoff file this custodian received the bundle
    # by (null when it arrived without one). Hashing it into the sealed receipt
    # is what makes the sender's claim strippable only before the recipient
    # seals, never after.
    if $rec.handoff != null and $rec.handoff !~ $SHA256_RE {
        error make {msg: $"receipt handoff must be null or a sha256 hex: ($rec.handoff | to json)"}
    }
}

# Deterministic bytes: keys in RECEIPT_KEYS order, compact JSON, one trailing
# newline — same byte discipline as link records, so independent tooling can
# reproduce the file. Receipts are NOT self-addressed: their authority is the
# custodian's signed seal root covering the file, not the filename.
export def receipt-bytes [rec: record]: nothing -> binary {
    validate-receipt $rec
    ($rec | select ...$RECEIPT_KEYS | to json --raw) + "\n" | into binary
}

# Read a receipt file and validate its shape. No self-addressing check —
# a receipt's authority is the seal covering it, not its filename.
export def read-receipt [file: path]: nothing -> record {
    let rec = open --raw $file | from json
    validate-receipt $rec
    $rec
}

# Path+sha256 manifest of a bundle's BIRTH files — everything except the
# custody/ layers — relative to the bundle root, sorted by path. What a
# receipt's `files` field commits to at import, and what verification
# recomputes to compare against it.
export def bundle-manifest [bundle: path]: nothing -> table {
    let root = $bundle | path expand
    glob --no-dir ($root | path join ** *)
    | path relative-to $root
    | where $it !~ $'^($CUSTODY_DIR)/'
    | sort
    | each {|p| {path: $p sha256: (open --raw ($root | path join $p) | hash sha256)} }
}

# The custody layers of a bundle, sorted by their claimed index; empty table
# for a birth bundle. The dirname index is transport only — verification
# enforces contiguity and the receipt chain against it.
export def custody-layers [bundle: path]: nothing -> table {
    let dir = custody-dir $bundle
    if not ($dir | path exists) {
        return []
    }
    glob ($dir | path join *)
    | each {|d|
        let idx = $d | path basename | parse --regex '^(?<index>\d+)-' | get --optional 0.index
        if $idx == null {
            error make {msg: $"malformed custody layer name: ($d) — expected <index>-<neuron-prefix>"}
        }
        {index: ($idx | into int) dir: $d}
    }
    | sort-by index
}

# The repo's own neuron identity: the CID of its single registered pubkey.
# init canonicalizes the key at registration, so the file bytes ARE the
# canonical form — hash them directly. Ambiguity (several registered keys)
# is an error: one keypair is one neuron, a custody claim needs exactly one.
export def own-neuron [root: path]: nothing -> string {
    let pubs = glob ($root | path join multiproofs pubkeys *.pub)
    if ($pubs | length) != 1 {
        error make {msg: $"cannot derive the custodian neuron: expected exactly one pubkey in multiproofs/pubkeys/, found ($pubs | length)"}
    }
    open --raw ($pubs | first) | into binary | cid-v0
}
