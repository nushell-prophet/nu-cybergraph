# The two special-case records, published. `particle add-edge` / `add-link` are
# the public face; `convention confirm` / `deny` mint the same records as their
# targets and come through here too, so one record has one construction site
# and one admission rule for its operands.
#
# Why a module of its own rather than the bodies living in `particle.nu`:
# `convention.nu` defines `export def update` — the name of a nushell builtin —
# and a module that shadows a builtin breaks the parse of every module it
# imports whose body uses that builtin. `particle.nu` uses `update`, so a
# direct import there fails to parse, by wholesale or by named list, with an
# error pointing at `particle.nu` and naming nothing about `update`.
#
# Not that the direct import is impossible: `alias core-update = update` at the
# top of `particle.nu`, called in place of the builtin, makes it parse
# (verified both ways). It is rejected as the fix, not as unavailable — the
# alias has to be repeated for every builtin name the two files come to share,
# and it puts the workaround in the file that shadows nothing. A module that
# shadows nothing needs no workaround at all, and this one uses no builtin
# either of them shadows.

use _particle.nu [ particle-store resolve-particle store-index ]
use _record.nu [ edge-bytes link-bytes ]
use _signer.nu [ resolve-signer ]

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
# `resolve-signer` and NOT `resolve-particle`: a signer CID names a pubkey file,
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
        signer: (resolve-signer $root $signer)
    } | particle-store $root
}
