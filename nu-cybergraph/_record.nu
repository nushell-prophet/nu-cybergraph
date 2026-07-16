# The link record — the atomic edge of the cybergraph — and its byte
# discipline. Spec-critical: README "Link record format" pins this section;
# tests/test_record.nu holds the golden bytes and CID.
#
# A record is content-addressed: the file is named by the CID v0 of its exact
# bytes. Writers MUST emit canonical bytes (fixed key order, compact JSON, one
# trailing newline) so independent writers of the same record produce the same
# CID. Readers verify the raw file bytes against the filename, so a
# non-canonical file still fails loudly instead of drifting.

use _deps.nu [cid-v0]

export const LINK_KEYS = [cid_from cid_to neuron claimed_at]

const CID_V0_RE = '^Qm[1-9A-HJ-NP-Za-km-z]{44}$'

export def validate-link [rec: record]: nothing -> nothing {
    let cols = $rec | columns
    if ($cols | sort) != ($LINK_KEYS | sort) {
        error make {msg: $"link record must have exactly keys ($LINK_KEYS | str join ', ') — got ($cols | str join ', ')"}
    }
    for key in [cid_from cid_to neuron] {
        if ($rec | get $key) !~ $CID_V0_RE {
            error make {msg: $"($key) must be a base58btc CID v0 \(Qm + 44 chars\): (($rec | get $key) | to json)"}
        }
    }
    # Parseability doubles as a charset guard: a datetime string contains no
    # `"` or `\`, so compact JSON serialization stays escape-free and the
    # canonical bytes stay trivially reproducible.
    try { $rec.claimed_at | into datetime | ignore } catch {
        error make {msg: $"claimed_at is not a parseable timestamp: ($rec.claimed_at | to json)"}
    }
}

# Canonical bytes: keys in LINK_KEYS order, compact JSON, one trailing "\n".
export def link-bytes [rec: record]: nothing -> binary {
    validate-link $rec
    ($rec | select ...$LINK_KEYS | to json --raw) + "\n" | into binary
}

# The record's content address — what the file must be named.
export def link-cid [rec: record]: nothing -> string {
    link-bytes $rec | cid-v0
}

# Read + validate a record file, enforcing self-addressing: the CID of the
# RAW bytes (not a re-serialization) must equal the filename stem, so any
# tampering or non-canonical rewrite fails here before anything trusts it.
export def read-link [file: path]: nothing -> record {
    let raw_cid = open --raw $file | into binary | cid-v0
    let stem = $file | path parse | get stem
    if $raw_cid != $stem {
        error make {msg: $"($file) does not match its content address: bytes hash to ($raw_cid)"}
    }
    let rec = open --raw $file | from json
    validate-link $rec
    $rec
}
