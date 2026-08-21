# Import a foreign link's bundle into this repo, verifying before anything
# lands. The bundle stays intact under imported/<signer-cid>/<edge-cid>/ — it
# remains the link's authority for authorship and birth time through any
# number of re-exports.
#
# Import also writes this repo's custody receipt under receipts/ — OUTSIDE
# the read-only imported copy — committing to the received bytes and chaining
# to the last custody layer. The next seal catalogues and freezes it; from
# then on `bundle` can re-export the link with this repo's custody layer
# appended.

use _repo.nu graph-root
use _layout.nu [ imported-dir receipt-relpath handoff-filename ]
use _fs.nu [ copy-tree cwd-relative ]
use _receipt.nu [ receipt-bytes bundle-manifest custody-layers ]
use _record.nu [ link-cid ]
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
    # Paths mirror the graph layout — the author's CID above, the edge below.
    # The receipt itself spells the act out in fields instead (_receipt.nu),
    # so nothing it asserts needs dereferencing.
    #
    # The triple is DERIVED here, not published. It used to be minted into the
    # custodian's store, and that comment said plainly the mint was intuitive
    # and load-bearing on nothing — so it went with the same rule that took
    # the mint out of `link add`: the store holds bytes something points at,
    # and importing an act points at nothing. Until this custodian makes an
    # act about the imported cyberlink, its CID dereferences to nothing here,
    # which is the honest state: nobody has said anything about it yet.
    let edge_cid = $v.leaf.filepath | path parse | get stem
    let link_cid = link-cid $v.record
    let dest = imported-dir $root | path join $v.signer.cid $edge_cid
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
        open --raw ($layers | last | get dir | path join (receipt-relpath $v.signer.cid $edge_cid)) | hash sha256
    }
    # Hash of the handoff we arrived by, pulled into the sealed chain — after
    # this repo seals, the sender's claim can no longer be stripped.
    let handoff = if $v.handed_to == null { null } else {
        let tail_dir = if ($layers | is-empty) { $dest } else { $layers | last | get dir }
        open --raw ($tail_dir | path join (handoff-filename $edge_cid)) | hash sha256
    }
    let receipt = {
        cid_from: $v.record.cid_from
        cid_to: $v.record.cid_to
        signer: $v.signer.cid
        custodian: $me
        received_at: (date now | format date "%+")
        files: (bundle-manifest $dest)
        prev: $prev
        handoff: $handoff
    }
    let receipt_path = $root | path join (receipt-relpath $v.signer.cid $edge_cid)
    mkdir ($receipt_path | path dirname)
    receipt-bytes $receipt | save --raw $receipt_path

    {
        edge: $edge_cid
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
