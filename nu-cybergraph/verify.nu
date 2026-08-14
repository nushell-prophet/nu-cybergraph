# Verify a link by CID — own or imported — always through its birth
# certificate and the seal it was born under, never the repo's current root.
#
# Returns a table, one row per verified copy: an own link has exactly one;
# the same CID imported from several signers yields one row each. One shape
# for both cases, so callers never branch on where the link came from.

use _repo.nu graph-root
use _layout.nu [ cert-path imported-copies snapshot-dir ]
use _verify-helpers.nu [ verify-bundle ]

# Verify a link — own or imported — against its birth seal, never the current
# root. One row per verified copy: own links have one, imports one per signer.
export def main [
    link_cid: string # Link CID: authored here (certs/) or imported (imported/*/)
    --repo: path # Repo root (default: git root of current directory)
]: nothing -> table {
    let root = graph-root $repo
    let cert = cert-path $root $link_cid
    if ($cert | path exists) {
        # Own link: still one verification path for everything — the same
        # checker, told where this link's proof and its seal's artifacts are,
        # so "verifies here" still means "verifies anywhere".
        #
        # It used to be told by construction instead: export a portable bundle
        # into a temp dir and check that, because `merkle verify` derived the
        # root statement from the same --repo as the content, and the graph
        # home's multiproofs/tree-root.txt is the CURRENT root — a certificate
        # from any earlier seal died on "proof is for a different seal". That
        # cost a mktemp and a full copy per link (~92ms each, 567 links on the
        # acceptance graph) to rearrange paths, never to check anything.
        # nu-multiproof 16e3e74's --multiproofs-dir names the older seal
        # directly; seals/<root12>/ is already that directory, snapshotted at
        # birth by `seal`.
        let born = open --raw $cert | from json | get root
        let snapshot = snapshot-dir $root $born
        if not ($snapshot | path exists) {
            error make {msg: $"seal snapshot missing for root ($born | str substring 0..11) — the certificate predates the seals/ convention?"}
        }
        [(verify-bundle $root --cert $cert --multiproofs-dir $snapshot)]
    } else {
        # The same link CID can arrive from several signers (identical record,
        # identical CID) — verify every copy we hold.
        let hits = imported-copies $root $link_cid
        if ($hits | is-empty) {
            error make {msg: $"unknown link: ($link_cid) — not in certs/ or imported/"}
        }
        $hits | each {|bundle_dir| verify-bundle $bundle_dir }
    }
}
