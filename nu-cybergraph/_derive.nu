# The derived-CID primitive — the one operation every convention stands on.
# Spec-critical byte format, pinned by golden tests in
# tests/test_convention.nu; same discipline as _record.nu. Changing the
# serialization breaks every derived CID — treat as a format version bump,
# not an edit.
#
# Canonical records are THIS REPO'S EXPERIMENT, not journal canon. bj002's
# appendix defines `hash(x, y, …)` as the CID of the arguments comma-joined;
# the journal issue that proposed records instead (bj002-1) was withdrawn on
# 2026-07-20 as a negative result — for the journal *text*, not for the code,
# which keeps testing the record form. Here a derived CID is the CID v0 of a
# *canonical record* — compact JSON, keys in alphabetical order, values
# strings only (no nesting: a reference to another record is its CID),
# exactly one trailing "\n". The appendix's two special cases are just
# records: the edge address is `derive {cid_from: A, cid_to: B}`, the
# cyberlink's derived CID is `derive {cid_from: A, cid_to: B, signer: S}`.
#
# The link *file* record (_record.nu) is serialized by the same rule —
# record-bytes is the one canon of the format. Since the file record is
# exactly the triple, the file's self-address and the act's derived CID are
# one CID: acts are addressed by the double and triple alone (bj002
# «Основы»), and the file in links/ is the published preimage of that address.
#
# Alphabetical means byte order of the UTF-8 key bytes — locale-free and
# case-sensitive; nushell's record `sort` matches it for these keys.

use _deps/cid-v0.nu [cid-v0]

# Canonical bytes of a record: keys sorted alphabetically, compact JSON, one
# trailing "\n". Values must be strings — flatness is the spec, not a
# convenience: one structure, one byte string, one CID. Published as a
# particle by the convention layer, the record is its own preimage
# (bj002 "Reading instructions").
export def record-bytes [rec: record]: nothing -> binary {
    for key in ($rec | columns) {
        let kind = $rec | get $key | describe
        if $kind != "string" {
            error make {msg: $"canonical record values must be strings — ($key) is ($kind); a reference to another record is its CID"}
        }
    }
    ($rec | sort | to json --raw) + "\n" | into binary
}

# The CID v0 of the record's canonical bytes — a derived CID.
export def derive [rec: record]: nothing -> string {
    record-bytes $rec | cid-v0
}
