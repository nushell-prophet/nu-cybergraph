# Verify a link by CID — own or imported — always through its birth
# certificate and the seal it was born under, never the repo's current root.
#
# Returns a table, one row per verified copy: an own link has exactly one;
# the same CID imported from several neurons yields one row each. One shape
# for both cases, so callers never branch on where the link came from.

use _repo.nu graph-root
use _verify-helpers.nu [verify-bundle]
use bundle.nu

export def main [
    link_cid: string # Link CID: authored here (certs/) or imported (imported/*/)
    --repo: path # Repo root (default: git root of current directory)
]: nothing -> table {
    let root = graph-root $repo
    if (($root | path join certs $"($link_cid).cert.json") | path exists) {
        # Own link: one verification path for everything — materialize the
        # portable bundle and check that, so "verifies here" always means
        # "verifies anywhere".
        let tmp = mktemp --directory
        let result = try {
            # Pass the caller's $repo through, not the resolved $root:
            # graph-root is not idempotent (it always appends cybergraph/),
            # so a resolved home must never be re-resolved.
            let b = if $repo != null {
                bundle $link_cid --repo $repo --out ($tmp | path join bundle)
            } else {
                bundle $link_cid --out ($tmp | path join bundle)
            }
            verify-bundle $b
        } catch {|e|
            rm -rf $tmp
            error make {msg: $e.msg}
        }
        rm -rf $tmp
        [$result]
    } else {
        # The same link CID can arrive from several neurons (identical record,
        # identical CID) — verify every copy we hold.
        let hits = glob ($root | path join imported * $link_cid)
        if ($hits | is-empty) {
            error make {msg: $"unknown link: ($link_cid) — not in certs/ or imported/"}
        }
        $hits | each {|bundle_dir| verify-bundle $bundle_dir }
    }
}
