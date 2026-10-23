use std/assert
use std/testing *

use ../nu-cybergraph/_record.nu [ link-bytes link-cid edge-bytes edge-cid validate-link validate-edge read-link LINK_KEYS EDGE_KEYS ]
use ../nu-cybergraph/_derive.nu [ derive ]
use ../nu-cybergraph/_deps/cid-v0.nu [ cid-v0 ]

# Fixed triple for golden pinning — same file/signer CIDs as the
# bostrom-journal bj003 smoke experiment. The pair is what a link file holds;
# the triple is written to no file until someone publishes it.
def golden-record []: nothing -> record {
    {
        cid_from: "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
        cid_to: "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
        signer: "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"
    }
}

def golden-pair []: nothing -> record {
    golden-record | reject signer
}

const GOLDEN_BYTES = '{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","signer":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"}'
const GOLDEN_CID = "QmRyRXXRM7ztFTPiyXjDtra9ND2oU64iE2jcydwubW17Ze"
const GOLDEN_EDGE_BYTES = '{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"}'
const GOLDEN_EDGE_CID = "QmUiARbMPT9WNXqvgb2BB9gWFXRiCEqD96AF5xebwNTCTT"
const GOLDEN_SIGNER = "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"

@test
def "the golden bytes have alphabetical key order as compact JSON with one trailing newline" [] {
    assert equal (edge-bytes (golden-pair) | decode) $"($GOLDEN_EDGE_BYTES)\n"
    assert equal (edge-cid (golden-pair)) $GOLDEN_EDGE_CID
    assert equal (link-bytes (golden-record) | decode) $"($GOLDEN_BYTES)\n"
    assert equal (link-cid (golden-record)) $GOLDEN_CID
}

# The file holds exactly the pair, so its self-address IS the edge address;
# the triple record's self-address IS the cyberlink's derived CID, whether or
# not anyone published those bytes. Both are plain `derive` under the one
# canon — bj002's two special cases.
@test
def "both addresses are plain derived CIDs under the one canon" [] {
    assert equal (edge-cid (golden-pair)) (derive (golden-pair))
    assert equal (link-cid (golden-record)) (derive (golden-record))
    assert not equal (edge-cid (golden-pair)) $GOLDEN_CID
}

# Two signers, one edge — the whole reason the edge is the file's address:
# the same pair under any signer is one file name, while the triples differ.
@test
def "the edge CID is the same for every signer of that edge" [] {
    let other = (golden-record) | update signer $GOLDEN_CID

    assert equal (edge-bytes ($other | reject signer)) (edge-bytes (golden-pair))
    assert not equal (link-cid $other) (link-cid (golden-record))
}

@test
def "input key order does not change the CID" [] {
    let reordered = {
        signer: "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"
        cid_to: "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
        cid_from: "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
    }

    assert equal (link-cid $reordered) $GOLDEN_CID
    assert equal (edge-cid ($reordered | reject signer)) $GOLDEN_EDGE_CID
}

@test
def "malformed records are rejected" [] {
    # Not a CID
    assert error {|| validate-edge ((golden-pair) | update cid_from "not-a-cid") }
    assert error {|| validate-link ((golden-record) | update cid_from "not-a-cid") }
    # CID v1 charset (0 and l are outside base58btc)
    assert error {|| validate-link ((golden-record) | update signer "Qm0l000000000000000000000000000000000000000000") }
    # Extra key — the removed claimed_at stays removed
    assert error {|| validate-edge ((golden-pair) | insert claimed_at "2026-07-16T00:00:00+00:00") }
    assert error {|| validate-link ((golden-record) | insert claimed_at "2026-07-16T00:00:00+00:00") }
    # The signer is not in the bytes: a pair carrying one is malformed
    assert error {|| validate-edge (golden-record) }
    # Missing key
    assert error {|| validate-edge ((golden-pair) | reject cid_to) }
    assert error {|| validate-link ((golden-record) | reject signer) }
    # The pre-`signer` shape is malformed, not legacy: the key-set check refuses
    # it like any other wrong record, so no reader can quietly read `neuron`.
    assert error {|| validate-link ((golden-record) | rename signer neuron) }
}

# A link file lives in its signer's directory; read-link returns the triple —
# pair from the bytes, signer from the path.
@test
def "read-link reads the pair from the file and the signer from the path" [] {
    let tmp = mktemp --directory

    mkdir ($tmp | path join $GOLDEN_SIGNER)
    let good = $tmp | path join $GOLDEN_SIGNER $"($GOLDEN_EDGE_CID).json"

    edge-bytes (golden-pair) | save --raw $good
    assert equal (read-link $good) (golden-record)
    rm --recursive --force $tmp
}

# The directory name is checked for FORM — it must be a CID v0 — because it
# is the only place the signer is written at all. The binding of path to
# signer is the seal's job, not read-link's.
@test
def "read-link refuses a file outside a signer directory" [] {
    let tmp = mktemp --directory

    mkdir ($tmp | path join "not-a-cid")
    let stray = $tmp | path join "not-a-cid" $"($GOLDEN_EDGE_CID).json"

    edge-bytes (golden-pair) | save --raw $stray
    let err = try { read-link $stray; null } catch {|e| $e.msg }

    assert ($err != null)
    assert ($err | str contains "signer directory")
    rm --recursive --force $tmp
}

@test
def "read-link enforces self-addressing on raw bytes" [] {
    let tmp = mktemp --directory

    mkdir ($tmp | path join $GOLDEN_SIGNER)

    # Same bytes under a wrong name: rejected before any field is trusted
    let other_pair = (golden-pair) | update cid_to (golden-pair).cid_from
    let renamed = $tmp | path join $GOLDEN_SIGNER $"(edge-cid $other_pair).json"

    edge-bytes (golden-pair) | save --raw $renamed
    assert error {|| read-link $renamed }

    # Semantically equal but non-canonical bytes (pretty-printed) under the
    # canonical name: rejected — the CID covers bytes, not meaning
    let pretty = $tmp | path join $GOLDEN_SIGNER $"($GOLDEN_EDGE_CID).json"

    (golden-pair) | to json --indent 2 | save --raw --force $pretty
    assert error {|| read-link $pretty }
    rm --recursive --force $tmp
}

@test
def "read-link rejects non-canonical bytes even under their own address" [] {
    let tmp = mktemp --directory

    mkdir ($tmp | path join $GOLDEN_SIGNER)
    # Each of these is a valid pair, self-addressed by its OWN CID — so the
    # filename check passes. Accepting them would give one act two addresses
    # and break the file's identity with the edge address.
    let variants = [
        # reordered keys
        ((golden-pair) | select cid_to cid_from | to json --raw)
        # added whitespace
        $"($GOLDEN_EDGE_BYTES | str replace '{' '{ ')"
        # duplicate key: `from json` keeps the LAST, so the first value is a
        # decoy no reader ever sees
        ($GOLDEN_EDGE_BYTES | str replace '{' $'{"cid_from":"($GOLDEN_CID)",')
    ]

    for bytes in $variants {
        let body = $"($bytes)\n"
        let file = $tmp | path join $GOLDEN_SIGNER $"(($body | into binary | cid-v0)).json"

        $body | save --raw --force $file
        let err = try { read-link $file; null } catch {|e| $e.msg }

        assert ($err != null) $"non-canonical bytes were accepted: ($bytes)"
        assert ($err | str contains "is not canonical bytes")
        assert ($err | str contains $GOLDEN_EDGE_CID) "the error must name the act's one address"
    }
    rm --recursive --force $tmp
}
