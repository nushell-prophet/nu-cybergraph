# The link record — the atomic edge of the cybergraph — and its byte
# discipline. Spec-critical: README "Link record format" pins this section;
# tests/test_record.nu holds the golden bytes and CID.
#
# A record is content-addressed: the file is named by the CID v0 of its exact
# bytes. Writers MUST emit canonical bytes (the one canon of _derive.nu:
# alphabetical key order, compact JSON, one trailing newline) so independent
# writers of the same record produce the same CID. Readers verify the raw file
# bytes against the filename, so a non-canonical file still fails loudly
# instead of drifting.

use _deps/cid-v0.nu [cid-v0]
use _derive.nu [record-bytes]

# Why alphabetical (not the semantic triple-first order): one serialization
# rule for every record in the format — link files and derived records alike —
# is simpler to explain and to port than a rule plus a pinned per-shape list.
#
# Why no claimed_at: the record is exactly the triple, so its self-address
# equals the act's derived CID (under the record form of `derive`, _derive.nu)
# — the same cyberlink recorded by
# anyone, at any time, is one file under one CID. Time is not the record's
# business: the provable bound comes from the birth seal, and an author's
# *claimed* time is a convention edge over the graph (`convention claimed-at`).
export const LINK_KEYS = [cid_from cid_to signer]

# Exported for _receipt.nu, _handoff.nu and convention.nu — they reuse the
# record's field disciplines. RFC3339_RE guards timestamps that live OUTSIDE
# link records (receipts, handoffs, claimed-at files): a link record
# itself carries no time.
export const CID_V0_RE = '^Qm[1-9A-HJ-NP-Za-km-z]{44}$'

export const RFC3339_RE = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$'

# Enforce the record shape: exact LINK_KEYS set, CID v0 values throughout.
# Errors on the first violation, returns nothing on success.
export def validate-link [rec: record]: nothing -> nothing {
    let cols = $rec | columns
    if ($cols | sort) != ($LINK_KEYS | sort) {
        error make {msg: $"link record must have exactly keys ($LINK_KEYS | str join ', ') — got ($cols | str join ', ')"}
    }
    for key in $LINK_KEYS {
        if ($rec | get $key) !~ $CID_V0_RE {
            error make {msg: $"($key) must be a base58btc CID v0 \(Qm + 44 chars\): (($rec | get $key) | to json)"}
        }
    }
}

# Canonical bytes: the shared canon — alphabetical keys, compact JSON, one
# trailing "\n". validate-link pins the shape; record-bytes owns the bytes.
export def link-bytes [rec: record]: nothing -> binary {
    validate-link $rec
    record-bytes $rec
}

# The record's content address — what the file must be named.
export def link-cid [rec: record]: nothing -> string {
    link-bytes $rec | cid-v0
}

# Read + validate a record file, enforcing BOTH addressing rules: the CID of
# the RAW bytes (not a re-serialization) must equal the filename stem, and
# those bytes must be the record's one canonical form. One read: hash and
# parse must see the same bytes — a second read could race with a file swap,
# parsing bytes the CID check never covered.
export def read-link [file: path]: nothing -> record {
    let bytes = open --raw $file | into binary
    let raw_cid = $bytes | cid-v0
    let stem = $file | path parse | get stem
    if $raw_cid != $stem {
        error make {msg: $"($file) does not match its content address: bytes hash to ($raw_cid)"}
    }
    # Explicit utf-8: bare `decode` GUESSES the encoding, so a UTF-16 file
    # parsed back to the same triple under its own (different) CID.
    let rec = $bytes | decode utf-8 | from json
    validate-link $rec
    # Self-addressing alone only proves the bytes are named by their own hash.
    # It does NOT pin them to the canon: reordered keys, added whitespace, or a
    # duplicate key (`from json` keeps the last, so the discarded value never
    # reaches a reader) each hash to some OTHER CID and pass the check above
    # under that name. The act would then live at two addresses, and the file
    # would stop being the preimage of the cyberlink's derived CID — the
    # identity README "Link record format" is built on.
    let canonical = record-bytes $rec
    if $bytes != $canonical {
        error make {msg: $"($file) is not canonical bytes for its record — one act has one address, and this record's is ($canonical | cid-v0)"}
    }
    $rec
}
