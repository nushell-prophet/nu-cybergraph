# Assemble the portable bundle for one link: everything a stranger needs to
# verify it offline, in the layout nu-multiproof's README pins under
# "Verifying without the origin repo".
#
# An OWN link (has a birth certificate in certs/) exports the birth bundle.
# An IMPORTED link re-exports: the foreign bundle copied unchanged — it stays
# the authority for authorship and birth time — plus this repo's custody
# layer appended under custody/<n>-<neuron12>/. A custody layer is itself a
# proof bundle in the same layout, over the receipt instead of the record,
# so the same verification machinery covers both.

use _repo.nu graph-root
use _layout.nu [
    links-dir exports-dir cert-path cert-filename snapshot-dir imported-dir
    receipt-relpath receipt-cert-path receipt-cert-filename custody-dir custody-layer-dirname
]
use _receipt.nu [read-receipt custody-layers]

# Copy one seal's verification artifacts into a proof dir: the snapshot's
# root statement + signatures, the signer pubkeys, and the OTS bundles
# committing to that root. Shared by the birth bundle and custody layers.
def assemble-seal-artifacts [root: path out: path root_hex: string] {
    let snap = snapshot-dir $root $root_hex
    if not ($snap | path exists) {
        error make {msg: $"seal snapshot missing for root ($root_hex) — the proof predates the seals/ convention?"}
    }
    mkdir ($out | path join multiproofs pubkeys)
    glob ($snap | path join *) | each {|f| cp $f ($out | path join multiproofs) }

    # Signer pubkeys, derived from the snapshot's sig names (tree-root.txt.<name>.sig).
    # Anchored regex, greedy middle: a signer name may itself contain ".sig",
    # which str replace's first-match semantics would mangle.
    let signers = glob ($snap | path join tree-root.txt.*.sig)
        | each {|s| $s | path basename | parse --regex '^tree-root\.txt\.(?<name>.+)\.sig$' | get --optional 0.name }
        | compact
    let copied = $signers | each {|name|
        let pub = $root | path join multiproofs pubkeys $"($name).pub"
        if ($pub | path exists) { cp $pub ($out | path join multiproofs pubkeys); $name } else { null }
    } | where $it != null
    if ($copied | is-empty) {
        error make {msg: "no signer pubkey found for the snapshot's signatures — the bundle could never verify"}
    }

    # OTS bundles committing to this root, matched by their frozen root
    # statement. Plain content match — discovery only; verify re-checks the
    # commitment cryptographically.
    let ots_bundles = glob ($root | path join multiproofs ots-timestamps tree-root.*)
        | where {|d|
            let frozen = $d | path join tree-root.txt
            ($frozen | path exists) and (open --raw $frozen | str contains $root_hex)
        }
    if ($ots_bundles | is-empty) {
        print "note: no OTS bundle for this root (sealed with --no-stamp?) — the bundle's timestamp will report absent"
    } else {
        mkdir ($out | path join multiproofs ots-timestamps)
        $ots_bundles | each {|d|
            cp -r $d ($out | path join multiproofs ots-timestamps ($d | path basename))
        }
    }
}

export def main [
    link_cid: string # CID of a link: authored here (certs/) or imported (imported/*/)
    --repo: path # Source repo root (default: git root of current directory)
    --out: path # Bundle destination (default: exports/<link_cid>)
]: nothing -> path {
    let root = graph-root $repo
    let out = if $out != null { $out | path expand } else { exports-dir $root | path join $link_cid }
    if ($out | path exists) {
        error make {msg: $"bundle destination already exists: ($out)"}
    }

    let cert = cert-path $root $link_cid
    if ($cert | path exists) {
        # Own link: the birth bundle
        let proof = open --raw $cert | from json
        mkdir (links-dir $out)
        cp ($root | path join $proof.leaf.filepath) (links-dir $out)
        cp $cert ($out | path join (cert-filename $link_cid))
        assemble-seal-artifacts $root $out $proof.root
        return $out
    }

    # Imported link: re-export with this repo's custody layer appended
    let hits = glob (imported-dir $root | path join * $link_cid)
    if ($hits | is-empty) {
        error make {msg: $"unknown link: ($link_cid) — no birth certificate in certs/ and nothing in imported/"}
    }
    let rcert = receipt-cert-path $root $link_cid
    if not ($rcert | path exists) {
        error make {msg: $"no frozen receipt proof for ($link_cid) — run `nu-cybergraph seal` after import, then re-export"}
    }
    cp -r ($hits | first) $out

    let receipt = read-receipt ($root | path join (receipt-relpath $link_cid))
    let index = (custody-layers $out | length) + 1
    let layer = custody-dir $out | path join (custody-layer-dirname $index $receipt.custodian)
    let proof = open --raw $rcert | from json
    mkdir ($layer | path join ((receipt-relpath $link_cid) | path dirname))
    cp ($root | path join (receipt-relpath $link_cid)) ($layer | path join (receipt-relpath $link_cid))
    cp $rcert ($layer | path join (receipt-cert-filename $link_cid))
    assemble-seal-artifacts $root $layer $proof.root
    $out
}
