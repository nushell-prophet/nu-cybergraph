# The link on disk — an edge record inside a signer directory — and its byte
# discipline. Spec-critical: README "Link record format" pins this section;
# tests/test_record.nu holds the golden bytes and CIDs.
#
# The operational unit is the edge, so the file holds exactly the pair
# {cid_from, cid_to} and is named by its content address:
# <root>/<signer-cid>/<edge-cid>.json. The signer is not in the bytes — it is
# the directory name, and the binding of pair to signer is the seal's: the
# path enters the signed root, so a file moved into another signer's
# directory breaks its own proof. What a reader can check locally is form
# (the directory name must be a CID v0), not the binding.
#
# The cyberlink — `derive {cid_from, cid_to, signer}`, bj002's triple — is
# still defined and still computed: pair from the file, signer from the path.
# It stopped being the file's name; the writer publishes the triple record as
# a particle instead, so the derived CID keeps a published preimage
# (`confirm A B S` targets that address, and without the preimage nothing
# dereferences it).
#
# Writers MUST emit canonical bytes (the one canon of _derive.nu:
# alphabetical key order, compact JSON, one trailing newline) so independent
# writers of the same edge produce the same file under the same CID. Readers
# verify the raw file bytes against the filename, so a non-canonical file
# still fails loudly instead of drifting.

use _deps/cid-v0.nu [ cid-v0 ]
use _derive.nu [ record-bytes ]
use _validate.nu [ assert-keys assert-cids CID_V0_RE ]

# The pair the file holds. Why no signer: it lives in the path (header above).
#
# Why no claimed_at: time is not the record's business — the provable bound
# comes from the birth seal, and a signer's *claimed* time is a convention
# edge over the graph (`convention claimed-at`).
export const EDGE_KEYS = [cid_from cid_to]

# The triple — the cyberlink record the writer publishes as a particle. Its
# derived CID is the act's address, the one `confirm A B S` computes.
export const LINK_KEYS = [cid_from cid_to signer]

# Enforce the on-disk shape: exact EDGE_KEYS set, CID v0 values throughout.
# Errors on the first violation, returns nothing on success.
export def validate-edge [rec: record]: nothing -> nothing {
    assert-keys $rec $EDGE_KEYS "edge record"
    assert-cids $rec $EDGE_KEYS "edge record"
}

# Enforce the particle shape: exact LINK_KEYS set, CID v0 values throughout.
export def validate-link [rec: record]: nothing -> nothing {
    assert-keys $rec $LINK_KEYS "link record"
    assert-cids $rec $LINK_KEYS "link record"
}

# Canonical bytes of the pair — the exact bytes of the link file.
export def edge-bytes [rec: record]: nothing -> binary {
    validate-edge $rec
    record-bytes $rec
}

# The edge address — what the file must be named.
export def edge-cid [rec: record]: nothing -> string {
    edge-bytes $rec | cid-v0
}

# Canonical bytes of the triple — what `link add` publishes as a particle.
# Bytes and not only the CID: the writer stores these bytes and takes the
# address back from the store, so the address it reports and the preimage it
# stores cannot drift apart.
export def link-bytes [rec: record]: nothing -> binary {
    validate-link $rec
    record-bytes $rec
}

# The cyberlink's derived CID — the published particle's address.
export def link-cid [rec: record]: nothing -> string {
    link-bytes $rec | cid-v0
}

# Read + validate one link: pair from the file, signer from the path —
# returns the triple. Enforces BOTH addressing rules on the file: the CID of
# the RAW bytes (not a re-serialization) must equal the filename stem, and
# those bytes must be the record's one canonical form. The signer directory
# is checked for FORM only — the CID v0 shape; its binding to the pair is the
# seal's (header above). One read: hash and parse must see the same bytes — a
# second read could race with a file swap, parsing bytes the CID check never
# covered.
export def read-link [file: path]: nothing -> record {
    let signer = $file | path dirname | path basename
    if $signer !~ $CID_V0_RE {
        error make {msg: $"($file) does not sit in a signer directory: ($signer) is not a base58btc CID v0, and the signer of a link is its directory's name"}
    }
    let bytes = open --raw $file | into binary
    let raw_cid = $bytes | cid-v0
    let stem = $file | path parse | get stem
    if $raw_cid != $stem {
        error make {msg: $"($file) does not match its content address: bytes hash to ($raw_cid)"}
    }
    # Explicit utf-8: bare `decode` GUESSES the encoding, so a UTF-16 file
    # parsed back to the same pair under its own (different) CID.
    let rec = $bytes | decode utf-8 | from json
    validate-edge $rec
    # Self-addressing alone only proves the bytes are named by their own hash.
    # It does NOT pin them to the canon: reordered keys, added whitespace, or a
    # duplicate key (`from json` keeps the last, so the discarded value never
    # reaches a reader) each hash to some OTHER CID and pass the check above
    # under that name. The act would then live at two addresses, and the file
    # would stop being the preimage of the edge address — the identity README
    # "Link record format" is built on.
    let canonical = record-bytes $rec
    if $bytes != $canonical {
        error make {msg: $"($file) is not canonical bytes for its record — one act has one address, and this record's is ($canonical | cid-v0)"}
    }
    $rec | insert signer $signer
}
