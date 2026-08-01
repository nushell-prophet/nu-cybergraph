# Verify a link by CID — own or imported — always through its birth
# certificate and the seal it was born under, never the repo's current root.
#
# Returns a table, one row per verified copy: an own link has exactly one;
# the same CID imported from several signers yields one row each. One shape
# for both cases, so callers never branch on where the link came from.

use _repo.nu graph-root
use _layout.nu [cert-path imported-copies]
use _verify-helpers.nu [verify-bundle]
use bundle.nu

# Verify a link — own or imported — against its birth seal, never the current
# root. One row per verified copy: own links have one, imports one per signer.
export def main [
    link_cid: string # Link CID: authored here (certs/) or imported (imported/*/)
    --repo: path # Repo root (default: git root of current directory)
]: nothing -> table {
    let root = graph-root $repo
    if ((cert-path $root $link_cid) | path exists) {
        # Own link: one verification path for everything — materialize the
        # portable bundle and check that, so "verifies here" always means
        # "verifies anywhere".
        let tmp = mktemp --directory
        let result = try {
            # Pass the caller's $repo through, not the resolved $root:
            # graph-root is not idempotent (it always appends cybergraph/),
            # so a resolved home must never be re-resolved.
            verify-bundle (bundle $link_cid --repo $repo --out ($tmp | path join bundle))
        } catch {|e|
            rm --recursive --force $tmp
            error make {msg: $e.msg}
        }
        rm --recursive --force $tmp
        [$result]
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
