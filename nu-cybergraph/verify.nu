# Verify an edge — who asserted it, and which of those acts is proven —
# always through each copy's birth certificate and the seal it was born
# under, never the repo's current root.
#
# Returns a table, one row per verified copy: one per own signer directory
# holding the edge, one per imported bundle carrying it. One shape for both
# cases, so callers never branch on where a copy came from.
#
# The argument is the EDGE address, not the cyberlink's derived CID: the two
# can only be told apart by trying, and a guessed argument fails silently.
# A caller holding a link CID dereferences it first: `particles/<link-cid>`
# holds the triple, which names the signer and the pair. It is there when some
# act named that cyberlink and published its preimage — no writer publishes it
# on the caller's behalf.

use _repo.nu graph-root
use _layout.nu [ signer-dirs link-path cert-path snapshot-dir imported-edge-copies ]
use _verify-helpers.nu [ verify-bundle ]

# Verify every copy of an edge against its birth seal, never the current
# root. `--signer` narrows to a single act.
export def main [
    edge_cid: string # Edge CID — the address of the pair, the filename of every copy
    --signer: string # Only this signer's act (default: every copy held)
    --repo: path # Repo root (default: git root of current directory)
]: nothing -> table {
    let root = graph-root $repo
    let held = signer-dirs $root
        | path basename
        | where $signer == null or $it == $signer
        | where ((link-path $root $it $edge_cid) | path exists)
    # An own copy with no certificate yet is pending its seal, not broken —
    # `link add` of an edge this repo also holds as an import is a supported
    # state between add and seal. Raising on it here aborted the WHOLE query
    # from inside the `each` (surfacing as "Eval block failed with pipeline
    # input", the trap seal.nu documents), hiding imported copies that still
    # verify. So a pending copy is set aside; it becomes the error only when
    # nothing verifiable is left — the is-empty branch below.
    let pending = $held | where {|s| not ((cert-path $root $s $edge_cid) | path exists) }
    let own = $held
        | where ((cert-path $root $it $edge_cid) | path exists)
        | each {|s|
            let cert = cert-path $root $s $edge_cid
            # Own copy: one verification path for everything — the same
            # checker, told where this act's proof and its seal's artifacts
            # are, so "verifies here" means "verifies anywhere".
            #
            # Told, not constructed. The graph home's multiproofs/tree-root.txt
            # is the CURRENT root, so a certificate from any earlier seal folds
            # against the wrong statement; nu-multiproof's --multiproofs-dir
            # names the birth seal directly, and seals/<root12>/ is already that
            # directory, snapshotted at birth by `seal`. Materializing a bundle
            # per link instead costs a mktemp and a full copy (~92ms each, 567
            # links on the acceptance graph) to rearrange paths, never to check
            # anything.
            let born = open --raw $cert | from json | get root
            let snapshot = snapshot-dir $root $born

            if not ($snapshot | path exists) {
                error make {msg: $"seal snapshot missing for root ($born | str substring 0..11) — the certificate predates the seals/ convention?"}
            }
            verify-bundle $root --cert $cert --multiproofs-dir $snapshot
        }
    let imported = imported-edge-copies $root $edge_cid
        | where $signer == null or signer == $signer
        | each {|h| verify-bundle $h.dir }
    let rows = $own ++ $imported

    if ($rows | is-empty) {
        if ($pending | is-not-empty) {
            error make {msg: $"($pending | first)/($edge_cid).json has no birth certificate yet — run `nu-cybergraph seal` first"}
        }
        error make {msg: $"unknown edge: ($edge_cid) — no signer directory holds it and nothing in imported/"}
    }
    $rows
}
