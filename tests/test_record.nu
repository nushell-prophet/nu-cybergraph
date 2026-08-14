use std/assert
use std/testing *

use ../nu-cybergraph/_record.nu [ link-bytes link-cid edge-cid validate-link read-link LINK_KEYS ]
use ../nu-cybergraph/_derive.nu [ derive ]
use ../nu-cybergraph/_deps/cid-v0.nu [ cid-v0 ]

# Fixed record for golden pinning — same file/signer CIDs as the
# bostrom-journal bj003 smoke experiment.
def golden-record []: nothing -> record {
    {
        cid_from: "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
        cid_to: "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
        signer: "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"
    }
}

const GOLDEN_BYTES = '{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","signer":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"}'
const GOLDEN_CID = "QmRyRXXRM7ztFTPiyXjDtra9ND2oU64iE2jcydwubW17Ze"
const GOLDEN_EDGE_CID = "QmUiARbMPT9WNXqvgb2BB9gWFXRiCEqD96AF5xebwNTCTT"

@test
def "golden bytes: alphabetical key order, compact JSON, one trailing newline" [] {
    assert equal (link-bytes (golden-record) | decode) $"($GOLDEN_BYTES)\n"
    assert equal (link-cid (golden-record)) $GOLDEN_CID
}

# The record is exactly the triple, so the file's self-address IS the act's
# derived CID: the link file is the preimage of the cyberlink's
# address, for every signer alike.
@test
def "link file CID equals the derived cyberlink CID" [] {
    assert equal (link-cid (golden-record)) (derive (golden-record))
}

# The second address of the same act: the edge without the signer. Pinned
# against `derive` on the pair, so the field can never drift away from bj002's
# edge address, and against the link CID, so the two can never be confused.
@test
def "the edge CID is the derived address of the pair without the signer" [] {
    assert equal (edge-cid (golden-record)) (derive ((golden-record) | reject signer))
    assert equal (edge-cid (golden-record)) $GOLDEN_EDGE_CID
    assert ((edge-cid (golden-record)) != $GOLDEN_CID)
}

# Two signers, one edge — the whole reason the edge has its own address.
@test
def "the edge CID is the same for every signer of that edge" [] {
    let other = (golden-record) | update signer $GOLDEN_CID
    assert equal (edge-cid $other) (edge-cid (golden-record))
    assert ((link-cid $other) != (link-cid (golden-record)))
}

@test
def "input key order does not change the CID" [] {
    let reordered = {
        signer: "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"
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
    assert error {|| validate-link ((golden-record) | update signer "Qm0l000000000000000000000000000000000000000000") }
    # Extra key — the removed claimed_at stays removed
    assert error {|| validate-link ((golden-record) | insert claimed_at "2026-07-16T00:00:00+00:00") }
    # Missing key
    assert error {|| validate-link ((golden-record) | reject signer) }
    # The pre-`signer` shape is malformed, not legacy: the key-set check refuses
    # it like any other wrong record, so no reader can quietly read `neuron`.
    assert error {|| validate-link ((golden-record) | rename signer neuron) }
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

    # Semantically equal but non-canonical bytes (pretty-printed) under the
    # canonical name: rejected — the CID covers bytes, not meaning
    let pretty = $tmp | path join $"($GOLDEN_CID).json"
    (golden-record) | to json --indent 2 | save --raw --force $pretty
    assert error {|| read-link $pretty }
    rm --recursive --force $tmp
}

@test
def "read-link rejects non-canonical bytes even under their own address" [] {
    let tmp = mktemp --directory
    # Each of these is a valid triple, self-addressed by its OWN CID — so the
    # filename check passes. Accepting them would give one act two addresses
    # and break the file's identity with the cyberlink's derived CID.
    let variants = [
        # reordered keys
        ((golden-record) | select signer cid_to cid_from | to json --raw)
        # added whitespace
        $"($GOLDEN_BYTES | str replace '{' '{ ')"
        # duplicate key: `from json` keeps the LAST, so the first value is a
        # decoy no reader ever sees
        ($GOLDEN_BYTES | str replace '{' $'{"cid_from":"($GOLDEN_CID)",')
    ]
    for bytes in $variants {
        let body = $"($bytes)\n"
        let file = $tmp | path join $"(($body | into binary | cid-v0)).json"
        $body | save --raw --force $file
        let err = try { read-link $file; null } catch {|e| $e.msg }
        assert ($err != null) $"non-canonical bytes were accepted: ($bytes)"
        assert ($err | str contains "is not canonical bytes")
        assert ($err | str contains $GOLDEN_CID) "the error must name the act's one address"
    }
    rm --recursive --force $tmp
}
