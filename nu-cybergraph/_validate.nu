# Field disciplines shared by every validated record in the format — link
# records, custody receipts, handoffs.
#
# The three validators used to repeat the same four checks with their own
# wording: exact key set, CID fields, RFC 3339 timestamp, sha256-or-null chain
# field. Each copy was a place for the rule to drift, and the drift would be
# invisible — a validator that accepts slightly more than its siblings does not
# fail, it lets a malformed artifact through. One definition per check, the
# artifact's name passed in so the message still says what was being read.
#
# The regexes live here for the same reason: they are the field types of the
# format, not the property of whichever record first needed one. `_record.nu`
# used to export them with an apology attached.

# The address type of everything in the graph: base58btc CID v0, `Qm` + 44
# base58 chars (the alphabet excludes 0, O, I and l).
export const CID_V0_RE = '^Qm[1-9A-HJ-NP-Za-km-z]{44}$'

# Timestamps live OUTSIDE link records (receipts, handoffs, claimed-at files) —
# a link record itself carries no time. Constrained charset, so a timestamp
# published as a file stays escape-free.
export const RFC3339_RE = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$'

# Lowercase hex sha256 — how one artifact commits to another's exact bytes.
export const SHA256_RE = '^[0-9a-f]{64}$'

# The shape gate: exactly these keys, no more and no fewer. Every validator
# starts here, so an unknown field is refused before any value is read.
export def assert-keys [rec: record keys: list<string> what: string]: nothing -> nothing {
    let cols = $rec | columns
    if ($cols | sort) != ($keys | sort) {
        error make {msg: $"($what) must have exactly keys ($keys | str join ', ') — got ($cols | str join ', ')"}
    }
}

# Fields that must each hold a CID v0.
export def assert-cids [rec: record keys: list<string> what: string]: nothing -> nothing {
    for key in $keys {
        if ($rec | get $key) !~ $CID_V0_RE {
            error make {msg: $"($what) ($key) must be a base58btc CID v0 \(Qm + 44 chars\): (($rec | get $key) | to json)"}
        }
    }
}

# An RFC 3339 timestamp field.
export def assert-timestamp [rec: record key: string what: string]: nothing -> nothing {
    if ($rec | get $key) !~ $RFC3339_RE {
        error make {msg: $"($what) ($key) is not an RFC 3339 timestamp: (($rec | get $key) | to json)"}
    }
}

# A sha256 field that may be null — the chain fields (prev, handoff, receipt),
# where null is the honest statement "there was no previous one", never a
# missing value.
export def assert-hash-or-null [rec: record key: string what: string]: nothing -> nothing {
    let value = $rec | get $key
    if $value != null and $value !~ $SHA256_RE {
        error make {msg: $"($what) ($key) must be null or a sha256 hex: ($value | to json)"}
    }
}
