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

use _fs.nu [list-files list-dirs]
use _derive.nu [ordered-bytes]
use _validate.nu [SHA256_RE assert-keys assert-cids assert-timestamp assert-hash-or-null]
use _layout.nu [CUSTODY_DIR custody-dir]

export const RECEIPT_KEYS = [link signer custodian received_at files prev handoff]

# Enforce the receipt shape: exact RECEIPT_KEYS set, CID fields, RFC 3339
# received_at, non-empty files manifest, hash-or-null chain fields (prev, handoff).
export def validate-receipt [rec: record]: nothing -> nothing {
    assert-keys $rec $RECEIPT_KEYS "receipt"
    assert-cids $rec [link signer custodian] "receipt"
    assert-timestamp $rec received_at "receipt"
    if ($rec.files | is-empty) {
        error make {msg: "receipt files manifest is empty"}
    }
    for f in $rec.files {
        if ($f | columns | sort) != [path sha256] or $f.sha256 !~ $SHA256_RE {
            error make {msg: $"malformed receipt files entry: ($f | to json --raw)"}
        }
    }
    assert-hash-or-null $rec prev "receipt"
    # `handoff`: sha256 of the handoff file this custodian received the bundle
    # by (null when it arrived without one). Hashing it into the sealed receipt
    # is what makes the sender's claim strippable only before the recipient
    # seals, never after.
    assert-hash-or-null $rec handoff "receipt"
}

# Deterministic bytes: keys in RECEIPT_KEYS order, compact JSON, one trailing
# newline — same byte discipline as link records, so independent tooling can
# reproduce the file. Receipts are NOT self-addressed: their authority is the
# custodian's signed seal root covering the file, not the filename.
export def receipt-bytes [rec: record]: nothing -> binary {
    validate-receipt $rec
    ordered-bytes $rec $RECEIPT_KEYS
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
    list-files $root --recursive
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
    list-dirs $dir
    | each {|d|
        let idx = $d | path basename | parse --regex '^(?<index>\d+)-' | get --optional 0.index
        if $idx == null {
            error make {msg: $"malformed custody layer name: ($d) — expected <index>-<signer-prefix>"}
        }
        {index: ($idx | into int) dir: $d}
    }
    | sort-by index
}
