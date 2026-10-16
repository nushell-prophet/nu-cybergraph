# The two special-case records, published. `particle add-edge` / `add-link` are
# the public face; `convention confirm-edge` / `confirm-link` / `deny-edge` /
# `deny-link` mint the same records as their targets, `update-edge` /
# `answer-edge` mint the pair as their subject, and all of them come through here too,
# so one record has one construction site and one admission rule for its
# operands. That is what the module is for.

use _particle.nu [ particle-store resolve-particle store-index ]
use _record.nu [ edge-bytes link-bytes ]
use _signer.nu [ reference-signer ]

# Publish the preimage of an edge address — the pair record — and return that
# address. Operands go through `resolve-particle`, the rule every write command
# applies: a CID must resolve to bytes this repo holds (`allow_missing` is the
# escape hatch), anything else is content, published first and named by its CID.
export def publish-edge [
    root: path
    cid_from: string
    cid_to: string
    allow_missing: bool
    literal: bool
]: nothing -> string {
    let index = store-index $root

    edge-bytes {
        cid_from: (resolve-particle $root $index $cid_from --allow-missing=$allow_missing --literal=$literal)
        cid_to: (resolve-particle $root $index $cid_to --allow-missing=$allow_missing --literal=$literal)
    } | particle-store $root
}

# The same for a cyberlink address — the triple. The signer goes through
# `reference-signer` and NOT `resolve-particle`: a signer CID names a pubkey file,
# which lives in multiproofs/pubkeys/, so checking it against particles/ would
# reject `own-signer`'s own answer (_signer.nu states the rule).
export def publish-link [
    root: path
    cid_from: string
    cid_to: string
    signer: string
    allow_missing: bool
    literal: bool
]: nothing -> string {
    let index = store-index $root

    link-bytes {
        cid_from: (resolve-particle $root $index $cid_from --allow-missing=$allow_missing --literal=$literal)
        cid_to: (resolve-particle $root $index $cid_to --allow-missing=$allow_missing --literal=$literal)
        signer: (reference-signer $root $signer)
    } | particle-store $root
}
