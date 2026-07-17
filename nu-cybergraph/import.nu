# Import a foreign link's bundle into this repo, verifying before anything
# lands. The bundle stays intact under imported/<neuron-cid>/<link-cid>/ — it
# remains the link's authority for authorship and birth time through any
# number of re-exports.
#
# Import also writes this repo's custody receipt under receipts/ — OUTSIDE
# the read-only imported copy — committing to the received bytes and chaining
# to the last custody layer. The next seal catalogues and freezes it; from
# then on `bundle` can re-export the link with this repo's custody layer
# appended.

use _repo.nu graph-root
use _layout.nu [imported-dir receipts-dir receipt-relpath]
use _receipt.nu [receipt-bytes bundle-manifest custody-layers own-neuron]
use _verify-helpers.nu [verify-bundle]

export def main [
    bundle: path # Portable bundle directory to import
    --repo: path # Destination repo root (default: git root of current directory)
]: nothing -> record {
    let root = graph-root $repo
    let v = verify-bundle $bundle
    if not $v.valid {
        error make {msg: $"refusing to import: ($v.error)"}
    }
    let link_cid = $v.leaf.filepath | path parse | get stem
    let dest = imported-dir $root | path join $v.neuron.cid $link_cid
    if ($dest | path exists) {
        error make {msg: $"already imported: ($dest)"}
    }
    mkdir ($dest | path dirname)
    cp -r ($bundle | path expand) $dest

    # The receipt commits to the bundle AS LANDED (its manifest is recomputed
    # from dest, not the source) and chains to the last custody layer present.
    let layers = custody-layers $dest
    let prev = if ($layers | is-empty) { null } else {
        open --raw ($layers | last | get dir | path join (receipt-relpath $link_cid)) | hash sha256
    }
    let receipt = {
        link: $link_cid
        neuron: $v.neuron.cid
        custodian: (own-neuron $root)
        received_at: (date now | format date "%+")
        files: (bundle-manifest $dest)
        prev: $prev
    }
    mkdir (receipts-dir $root)
    let receipt_path = $root | path join (receipt-relpath $link_cid)
    receipt-bytes $receipt | save --raw $receipt_path

    {
        link: $link_cid
        neuron: $v.neuron.cid
        path: $dest
        receipt: $receipt_path
        custody: ($v.custody | length)
        ots: $v.ots.status
    }
}
