# Import a foreign link's bundle into this repo, verifying before anything
# lands. The bundle stays intact under imported/<signer-cid>/<link-cid>/ — it
# remains the link's authority for authorship and birth time through any
# number of re-exports.
#
# Import also writes this repo's custody receipt under receipts/ — OUTSIDE
# the read-only imported copy — committing to the received bytes and chaining
# to the last custody layer. The next seal catalogues and freezes it; from
# then on `bundle` can re-export the link with this repo's custody layer
# appended.

use _repo.nu graph-root
use _layout.nu [ imported-dir receipts-dir receipt-relpath handoff-filename ]
use _fs.nu [ copy-tree cwd-relative ]
use _receipt.nu [ receipt-bytes bundle-manifest custody-layers ]
use _signer.nu [ own-signer ]
use _verify-helpers.nu [ verify-bundle ]

# Verify a foreign bundle and land it read-only under imported/, writing this
# repo's custody receipt for the next seal to freeze. Refuses on any
# verification failure and on a handoff addressed to another signer.
export def main [
    bundle: path # Portable bundle directory to import
    --repo: path # Destination repo root (default: git root of current directory)
]: nothing -> record {
    let root = graph-root $repo
    let v = verify-bundle $bundle
    if not $v.valid {
        error make {msg: $"refusing to import: ($v.error)"}
    }
    let me = own-signer $root
    # A bundle handed to someone else must not land here: this repo's custody
    # layer could never verify (the chain demands the previous holder's
    # handoff name THIS custodian), so fail before anything mutates.
    if $v.handed_to != null and $v.handed_to != $me {
        error make {msg: $"refusing to import: bundle was handed to ($v.handed_to), not to this repo's signer ($me)"}
    }
    let link_cid = $v.leaf.filepath | path parse | get stem
    let dest = imported-dir $root | path join $v.signer.cid $link_cid
    if ($dest | path exists) {
        error make {msg: $"already imported: ($dest)"}
    }
    mkdir ($dest | path dirname)
    # copy-tree, not `cp --recursive`: `cp` reports an unreadable source on
    # stderr and exits 0, and the receipt below is recomputed FROM $dest — so a
    # silently short copy would be frozen as the canonical file set, with every
    # later verification passing over the truncation.
    copy-tree $bundle $dest

    # The receipt commits to the bundle AS LANDED (its manifest is recomputed
    # from dest, not the source) and chains to the last custody layer present.
    let layers = custody-layers $dest
    let prev = if ($layers | is-empty) { null } else {
        open --raw ($layers | last | get dir | path join (receipt-relpath $link_cid)) | hash sha256
    }
    # Hash of the handoff we arrived by, pulled into the sealed chain — after
    # this repo seals, the sender's claim can no longer be stripped.
    let handoff = if $v.handed_to == null { null } else {
        let tail_dir = if ($layers | is-empty) { $dest } else { $layers | last | get dir }
        open --raw ($tail_dir | path join (handoff-filename $link_cid)) | hash sha256
    }
    let receipt = {
        link: $link_cid
        signer: $v.signer.cid
        custodian: $me
        received_at: (date now | format date "%+")
        files: (bundle-manifest $dest)
        prev: $prev
        handoff: $handoff
    }
    mkdir (receipts-dir $root)
    let receipt_path = $root | path join (receipt-relpath $link_cid)
    receipt-bytes $receipt | save --raw $receipt_path

    {
        link: $link_cid
        signer: $v.signer.cid
        path: ($dest | cwd-relative)
        receipt: ($receipt_path | cwd-relative)
        custody: ($v.custody | length)
        # The link's date, and the only one: the anchor over the signature that
        # endorsed it. Reached without a `?` because the refusal above already
        # rejected an unbound signer, and a bound one always has a row.
        endorsed: $v.signer.endorsed.status
    }
}
