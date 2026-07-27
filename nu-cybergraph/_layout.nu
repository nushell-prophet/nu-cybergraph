# Filesystem layout of the cybergraph home. One source of truth for every
# path the module reads or writes under the graph root — same lesson as
# nu-multiproof's _layout.nu: a layout change is one edit here, not six files
# silently disagreeing. Paths into multiproofs/ stay inline at call sites —
# they pin nu-multiproof's public layout, not ours.

use _fs.nu list-dirs

export const LINKS_DIR = "links"
export const PARTICLES_DIR = "particles"
export const CERTS_DIR = "certs"
export const SEALS_DIR = "seals"
export const EXPORTS_DIR = "exports"
export const IMPORTED_DIR = "imported"
export const RECEIPTS_DIR = "receipts"
export const CUSTODY_DIR = "custody"

# <root>/links
export def links-dir [root: path]: nothing -> path {
    $root | path join $LINKS_DIR
}

# <root>/particles — any self-addressed particle: instruction/address records
# (published so a reader can dereference an instruction edge, bj002 "Reading
# instructions") and content published by `particle add` or by a text argument
# to a write command. Not in the seal manifest: a particle is anchored the
# moment a sealed link names its CID (README "Graph home").
export def particles-dir [root: path]: nothing -> path {
    $root | path join $PARTICLES_DIR
}

# Extension a particle filename may carry after the CID: dot-separated
# alphanumeric segments ("md", "tar.gz"), no leading dot. One canon for the
# write side (`particle-store --ext` validates against it) and the read side
# (`particle-files` recognizes store files by it).
export const PARTICLE_EXT_RE = '^[A-Za-z0-9]+(\.[A-Za-z0-9]+)*$'

# <root>/particles/<cid> — one particle, self-addressed by the CID v0 of its
# exact bytes. `--ext` appends a filename extension (`<cid>.md`) — presentation
# convenience only (e.g. a forge renders .md); the address is always the bare
# CID, and readers resolve it whatever extension the file carries.
export def particle-path [root: path cid: string --ext: string]: nothing -> path {
    let name = if $ext == null { $cid } else { $"($cid).($ext)" }
    particles-dir $root | path join $name
}

# <root>/certs
export def certs-dir [root: path]: nothing -> path {
    $root | path join $CERTS_DIR
}

# <root>/seals
export def seals-dir [root: path]: nothing -> path {
    $root | path join $SEALS_DIR
}

# <root>/exports
export def exports-dir [root: path]: nothing -> path {
    $root | path join $EXPORTS_DIR
}

# <root>/imported
export def imported-dir [root: path]: nothing -> path {
    $root | path join $IMPORTED_DIR
}

# <root>/receipts
export def receipts-dir [root: path]: nothing -> path {
    $root | path join $RECEIPTS_DIR
}

# Every copy of one link we hold: imported/<neuron>/<link>, over all neurons.
# A two-level walk by listing, never `glob (… | path join * $link_cid)` — the
# graph path is spliced into that pattern, so a `[` in it returns [] and the
# caller reads "unknown link" for a link sitting right there.
export def imported-copies [root: path link_cid: string]: nothing -> list<path> {
    list-dirs (imported-dir $root)
    | each {|neuron| $neuron | path join $link_cid }
    | where {|d| $d | path exists }
}

# receipts/<cid>.receipt.json — the custody receipt's manifest path, relative
# to the graph root. Relative because it doubles as the proof's leaf.filepath:
# a custody layer places the receipt at this same path inside the layer dir.
export def receipt-relpath [link_cid: string]: nothing -> string {
    [$RECEIPTS_DIR $"($link_cid).receipt.json"] | path join
}

# <cid>.receipt.cert.json — the frozen receipt proof, also at a layer's root
export def receipt-cert-filename [link_cid: string]: nothing -> string {
    $"($link_cid).receipt.cert.json"
}

# <root>/receipts/<cid>.receipt.cert.json
export def receipt-cert-path [root: path link_cid: string]: nothing -> path {
    receipts-dir $root | path join (receipt-cert-filename $link_cid)
}

# <bundle>/custody — the appended custody layers of a re-exported bundle
export def custody-dir [bundle: path]: nothing -> path {
    $bundle | path join $CUSTODY_DIR
}

# custody/<index>-<neuron-cid-prefix> — one custody layer. The index makes the
# intended order readable; verification enforces it against the receipt chain,
# so a renamed or renumbered layer fails instead of lying silently.
export def custody-layer-dirname [index: int neuron_cid: string]: nothing -> string {
    $"($index)-($neuron_cid | str substring 0..11)"
}

# <cid>.handoff.json — the sender's signed handoff, at the root of the proof
# dir it leaves from: the bundle root for the author, the sender's custody
# layer for a custodian.
export def handoff-filename [link_cid: string]: nothing -> string {
    $"($link_cid).handoff.json"
}

# <cid>.cert.json — the certificate filename, also used at a bundle's root
export def cert-filename [link_cid: string]: nothing -> string {
    $"($link_cid).cert.json"
}

# <root>/links/<cid>.json — the record's self-addressed home
export def link-path [root: path cid: string]: nothing -> path {
    links-dir $root | path join $"($cid).json"
}

# <root>/certs/<cid>.cert.json — the frozen birth certificate
export def cert-path [root: path link_cid: string]: nothing -> path {
    certs-dir $root | path join (cert-filename $link_cid)
}

# <root>/seals/<root-hex-12> — the 12-char truncation is a layout contract:
# seal writes the snapshot there, bundle looks it up by the certificate's root.
export def snapshot-dir [root: path root_hex: string]: nothing -> path {
    seals-dir $root | path join ($root_hex | str substring 0..11)
}
