use std/assert
use std/testing *

use ../nu-cybergraph/_record.nu [link-bytes link-cid validate-link read-link LINK_KEYS]

# Fixed record for golden pinning — same particle/neuron CIDs as the
# bostrom-journal bj003 smoke experiment.
def golden-record []: nothing -> record {
    {
        cid_from: "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
        cid_to: "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
        neuron: "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"
        claimed_at: "2026-07-16T00:00:00+00:00"
    }
}

const GOLDEN_BYTES = '{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","claimed_at":"2026-07-16T00:00:00+00:00","neuron":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"}'
const GOLDEN_CID = "Qmeha3MmsWAhhT5AJFi8vWk9yHwNBMuaaUJmJCwztNU4cC"

@test
def "golden bytes: alphabetical key order, compact JSON, one trailing newline" [] {
    assert equal (link-bytes (golden-record) | decode) $"($GOLDEN_BYTES)\n"
    assert equal (link-cid (golden-record)) $GOLDEN_CID
}

@test
def "input key order does not change the CID" [] {
    let reordered = {
        claimed_at: "2026-07-16T00:00:00+00:00"
        neuron: "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"
        cid_to: "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
        cid_from: "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
    }
    assert equal (link-cid $reordered) $GOLDEN_CID
}

@test
def "malformed records are rejected" [] {
    # Not a CID
    assert error {|| validate-link ((golden-record) | update cid_from "not-a-cid") }
    # CID v1 charset (0 and l are outside base58btc)
    assert error {|| validate-link ((golden-record) | update neuron "Qm0l000000000000000000000000000000000000000000") }
    # Extra key
    assert error {|| validate-link ((golden-record) | insert note "hi") }
    # Missing key
    assert error {|| validate-link ((golden-record) | reject claimed_at) }
    # Unparseable timestamp
    assert error {|| validate-link ((golden-record) | update claimed_at "yesterday-ish") }
    # Parseable but not RFC 3339 — the spec pins the shape, not just parseability
    assert error {|| validate-link ((golden-record) | update claimed_at "2026-07-16") }
    # RFC 3339 shape but impossible date
    assert error {|| validate-link ((golden-record) | update claimed_at "2026-13-01T00:00:00+00:00") }
}

@test
def "read-link enforces self-addressing on raw bytes" [] {
    let tmp = mktemp --directory
    # Correctly-addressed file reads back
    let good = $tmp | path join $"($GOLDEN_CID).json"
    link-bytes (golden-record) | save --raw $good
    assert equal (read-link $good) (golden-record)

    # Same bytes under a wrong name: rejected before any field is trusted
    let renamed = $tmp | path join $"(link-cid ((golden-record) | update claimed_at '2027-01-01T00:00:00+00:00')).json"
    link-bytes (golden-record) | save --raw $renamed
    assert error {|| read-link $renamed }

    # Semantically equal but non-canonical bytes (pretty-printed): rejected —
    # the CID covers bytes, not meaning
    let pretty = $tmp | path join $"($GOLDEN_CID).json"
    (golden-record) | to json --indent 2 | save --raw --force $pretty
    assert error {|| read-link $pretty }
    rm --recursive --force $tmp
}
