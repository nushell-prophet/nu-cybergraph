use std/assert
use std/testing *

use ../nu-cybergraph/_handoff.nu [ handoff-bytes validate-handoff read-handoff HANDOFF_SCHEMA HANDOFF_KEYS ]
use ../nu-cybergraph/_derive.nu [ record-bytes ]
use ../nu-cybergraph/_deps/cid-v0.nu [ cid-v0 ]

# Fixed handoff for golden pinning: the golden link record of test_record.nu —
# its pair and its signer spelled out, which together derive the golden triple
# CID QmRyRX… that v1 of this format carried as a single `link` field.
#
# It is the AUTHOR's handoff, so `from` is the record's own signer and
# `receipt` is null. `to` is the golden edge CID standing in for a recipient,
# following this suite's convention of using file CIDs as signer CIDs — and
# deliberately different from every other value here, so a field read off by
# one cannot pass unnoticed.
def golden-handoff []: nothing -> record {
    {
        schema: "cybergraph-handoff-v2"
        cid_from: "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
        cid_to: "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
        signer: "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"
        from: "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"
        to: "QmUiARbMPT9WNXqvgb2BB9gWFXRiCEqD96AF5xebwNTCTT"
        receipt: null
        handed_at: "2026-07-27T00:00:00+00:00"
    }
}

const GOLDEN_BYTES = '{"schema":"cybergraph-handoff-v2","cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","signer":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr","from":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr","to":"QmUiARbMPT9WNXqvgb2BB9gWFXRiCEqD96AF5xebwNTCTT","receipt":null,"handed_at":"2026-07-27T00:00:00+00:00"}'

# Cross-checked with `sha256sum` on the saved file, not taken from the code it
# pins. This is the digest the recipient's receipt carries in its `handoff`
# field, so it is a byte pin on the custody chain as much as on the signature.
const GOLDEN_SHA256 = "65731236a5d63c4aa23bd7bf63ee6f6a0ad8fc4bd14df9ae73e1837d0fd1144b"

# These are the bytes ssh-keygen signs. Changing them invalidates every
# existing handoff signature and every receipt that hashed one — a format
# version bump, not an edit.
@test
def "the golden bytes follow the handoff key order as compact JSON with one trailing newline" [] {
    assert equal (handoff-bytes (golden-handoff) | decode) $"($GOLDEN_BYTES)\n"
    assert equal (handoff-bytes (golden-handoff) | hash sha256) $GOLDEN_SHA256
}

# The act is stated, not addressed — but the address is not lost: the three
# components derive back to the very CID v1 carried as its `link` field, the
# golden triple of test_record.nu. That is what makes the two notations
# equivalent, and so what makes dropping the compact one costless.
@test
def "the stated components derive back to the cyberlink CID" [] {
    let act = (golden-handoff) | select cid_from cid_to signer

    assert equal (record-bytes $act | cid-v0) "QmRyRXXRM7ztFTPiyXjDtra9ND2oU64iE2jcydwubW17Ze"
}

# Domain separation lives in the signed bytes, because every signature this
# toolchain makes is under the one generic `file` namespace. The tag can only
# do that job if it is the first thing in the bytes.
@test
def "the signed bytes open with the schema token" [] {
    assert ((handoff-bytes (golden-handoff) | decode) | str starts-with $'{"schema":"($HANDOFF_SCHEMA)"')
    assert equal ($HANDOFF_KEYS | first) "schema"
}

@test
def "input key order does not change the signed bytes" [] {
    let reordered = (golden-handoff) | select handed_at receipt to from signer cid_to cid_from schema

    assert equal (handoff-bytes $reordered | decode) $"($GOLDEN_BYTES)\n"
}

# Byte-exact, like parse-root-statement: a wrong or drifted token is a
# different format, never something to tolerate and read anyway.
@test
def "the schema token is required byte-exact" [] {
    # v1 is the previous format — it named the act by one derived CID. A reader
    # must refuse it outright, never read it as if the fields lined up.
    assert error {|| validate-handoff ((golden-handoff) | update schema "cybergraph-handoff-v1") }
    assert error {|| validate-handoff ((golden-handoff) | update schema "Cybergraph-Handoff-v2") }
    assert error {|| validate-handoff ((golden-handoff) | update schema $"($HANDOFF_SCHEMA) ") }
    assert error {|| validate-handoff ((golden-handoff) | update schema null) }
    # A pre-tag handoff carried no version claim at all — the key-set check
    # refuses it, so no reader can quietly accept an untagged one.
    assert error {|| validate-handoff ((golden-handoff) | reject schema) }
}

@test
def "malformed handoffs are rejected" [] {
    assert error {|| validate-handoff ((golden-handoff) | update cid_from "not-a-cid") }
    assert error {|| validate-handoff ((golden-handoff) | update signer "not-a-cid") }
    # v1's field name must not slip back in beside the components
    assert error {|| validate-handoff ((golden-handoff) | insert link "QmRyRXXRM7ztFTPiyXjDtra9ND2oU64iE2jcydwubW17Ze") }
    # CID v1 charset (0 and l are outside base58btc)
    assert error {|| validate-handoff ((golden-handoff) | update to "Qm0l000000000000000000000000000000000000000000") }
    assert error {|| validate-handoff ((golden-handoff) | update receipt "deadbeef") }
    assert error {|| validate-handoff ((golden-handoff) | update handed_at "2026-07-27") }
    assert error {|| validate-handoff ((golden-handoff) | insert note "hello") }
}

# receipt is null for the author, who has no receipt, and a sha256 hex for a
# custodian — the exact chain state handed over.
@test
def "receipt is null or a sha256 hex" [] {
    validate-handoff (golden-handoff)
    validate-handoff ((golden-handoff) | update receipt $GOLDEN_SHA256)
}

@test
def "read-handoff validates what it reads" [] {
    let tmp = mktemp --directory
    let good = $tmp | path join good.handoff.json

    handoff-bytes (golden-handoff) | save --raw $good
    assert equal (read-handoff $good) (golden-handoff)

    let bad = $tmp | path join bad.handoff.json

    ((golden-handoff) | update schema "cybergraph-handoff-v1" | to json --raw) | save --raw $bad
    assert error {|| read-handoff $bad }
    rm --recursive --force $tmp
}
