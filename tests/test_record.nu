use std/assert
use std/testing *

use ../nu-cybergraph/_record.nu [link-bytes link-cid validate-link read-link LINK_KEYS]
use ../nu-cybergraph/_derive.nu [derive]

# Fixed record for golden pinning — same particle/neuron CIDs as the
# bostrom-journal bj003 smoke experiment.
def golden-record []: nothing -> record {
    {
        cid_from: "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
        cid_to: "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
        neuron: "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"
    }
}

const GOLDEN_BYTES = '{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","neuron":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"}'
const GOLDEN_CID = "QmQoY7wbGV6797ErgTf39eMAeXuGbm5ZRHay4XTcoHMMvU"

@test
def "golden bytes: alphabetical key order, compact JSON, one trailing newline" [] {
    assert equal (link-bytes (golden-record) | decode) $"($GOLDEN_BYTES)\n"
    assert equal (link-cid (golden-record)) $GOLDEN_CID
}

# The record is exactly the triple, so the file's self-address IS the act's
# derived CID (bj002-1): the link file is the preimage of the cyberlink's
# address, for every neuron alike.
@test
def "link file CID equals the derived cyberlink CID" [] {
    assert equal (link-cid (golden-record)) (derive (golden-record))
}

@test
def "input key order does not change the CID" [] {
    let reordered = {
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
    # Extra key — the removed claimed_at stays removed
    assert error {|| validate-link ((golden-record) | insert claimed_at "2026-07-16T00:00:00+00:00") }
    # Missing key
    assert error {|| validate-link ((golden-record) | reject neuron) }
}

@test
def "read-link enforces self-addressing on raw bytes" [] {
    let tmp = mktemp --directory
    # Correctly-addressed file reads back
    let good = $tmp | path join $"($GOLDEN_CID).json"
    link-bytes (golden-record) | save --raw $good
    assert equal (read-link $good) (golden-record)

    # Same bytes under a wrong name: rejected before any field is trusted
    let renamed = $tmp | path join $"(link-cid ((golden-record) | update cid_to (golden-record).cid_from)).json"
    link-bytes (golden-record) | save --raw $renamed
    assert error {|| read-link $renamed }

    # Semantically equal but non-canonical bytes (pretty-printed): rejected —
    # the CID covers bytes, not meaning
    let pretty = $tmp | path join $"($GOLDEN_CID).json"
    (golden-record) | to json --indent 2 | save --raw --force $pretty
    assert error {|| read-link $pretty }
    rm --recursive --force $tmp
}
