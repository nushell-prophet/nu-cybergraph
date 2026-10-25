# The engine behind every convention verb (convention.nu): `address` interprets
# the grammar, `edge` writes the result. Internal, so a direct
# `use nu-cybergraph/convention.nu` shows the verbs alone.

use _repo.nu graph-root
use _derive.nu [ record-bytes ]
use _particle.nu [ particle-store resolve-particle store-index ]
use _signer.nu [ resolve-signer ]
use link.nu

# Resolve an address expression to a CID. A leaf string is an operand —
# `resolve-particle` turns content into its CID and leaves a CID alone (or
# refuses it, unresolved locally, unless allow_missing). A record has its
# values resolved first (a nested record becomes its CID), except the `op`
# value, which is the format's own word and never an operand; the flat result
# is then published as a self-addressed file and its CID returned. The one
# place the grammar is interpreted.
#
# `index` is built once by the caller and threaded through the recursion —
# one call resolves every operand of the source and the target, and
# rebuilding it per operand is the scan-per-lookup cost
# `resolve-particle`'s own doc comment measures against.
export def address [root: path index: record expr: any allow_missing: bool literal: bool]: nothing -> string {
    if ($expr | describe) == "string" { return (resolve-particle $root $index $expr --allow-missing=$allow_missing --literal=$literal) }
    let resolved = $expr | columns | reduce --fold {} {|key acc|
            $acc | insert $key (if $key == "op" { $expr.op } else { address $root $index ($expr | get $key) $allow_missing $literal })
        }

    record-bytes $resolved | particle-store $root
}

# Write a convention's edge: resolve the source and target expressions, then
# emit through `link add` so the triple guard, self-addressing and signer
# resolution all come from one place. The verbs forward their signer/repo/
# allow-missing controls here unchanged.
#
# `link add` gets --allow-missing unconditionally here, not $allow_missing:
# `address` above already resolved src/tgt down to CIDs that are guaranteed
# local (freshly published, or already checked against $allow_missing) — a
# second check on the same values in `link add` would be dead weight (another
# full index build) enforcing nothing the first check did not already settle.
export def edge [
    src: any # source address expression
    tgt: any # target address expression
    signer: oneof<string, nothing> # signer key override or null
    keyless_signer: oneof<string, nothing> # keyless signer name or null
    repo: oneof<path, nothing> # target repo or null
    allow_missing: bool # skip the local-file check on a CID operand
    literal: bool # treat a content operand as literal even if it names a path
]: nothing -> record {
    let root = graph-root $repo
    # Same order as `link add`, for the same reason: `address` publishes every
    # record it mints, so a signer resolved after it would leave those files
    # behind when the repo cannot name one. Through `resolve-signer` and not an
    # inline own-signer call, so a --keyless-signer name means the same thing
    # on both write paths. Resolved here and passed down as a CID, so `link add`
    # takes it as given rather than asking a second time.
    let signer_cid = resolve-signer $root $signer $keyless_signer
    let index = store-index $root

    link add (address $root $index $src $allow_missing $literal) (address $root $index $tgt $allow_missing $literal) --signer $signer_cid --repo $repo --allow-missing
}
