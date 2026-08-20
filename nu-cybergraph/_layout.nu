# Filesystem layout of the cybergraph home. One source of truth for every
# path the module reads or writes under the graph root — same lesson as
# nu-multiproof's _layout.nu: a layout change is one edit here, not six files
# silently disagreeing. Paths into multiproofs/ stay inline at call sites —
# they pin nu-multiproof's public layout, not ours.

use _fs.nu [ list-dirs list-files ]
use _validate.nu CID_V0_RE

export const PARTICLES_DIR = "particles"
export const CERTS_DIR = "certs"
export const SEALS_DIR = "seals"
export const EXPORTS_DIR = "exports"
export const IMPORTED_DIR = "imported"
export const RECEIPTS_DIR = "receipts"
export const CUSTODY_DIR = "custody"

# <root>/<signer-cid> — a signer's directory: every link this signer asserted,
# one edge file each. Signer directories sit at the graph root; the CID v0
# name is what tells them from the reserved directories (particles, certs,
# seals, ...), which never match that form.
export def signer-dir [root: path signer: string]: nothing -> path {
    $root | path join $signer
}

# Every signer directory present at the root — the walk behind cross-signer
# reads ("who asserted this edge"). Form only: a directory named by a CID v0
# is a signer's; whether its files belong to that signer is the seal's
# business, not the layout's.
export def signer-dirs [root: path]: nothing -> list<path> {
    list-dirs $root | where ($it | path basename) =~ $CID_V0_RE
}

# <root>/particles — the particle store, every file self-addressed: instruction and
# address records (published so a reader can dereference an instruction edge,
# bj002 "Reading instructions") and content published by `particle add` or by a
# text argument to a write command. Not in the seal manifest: a stored file is
# anchored the moment a sealed link names its CID (README "Graph home").
export def particles-dir [root: path]: nothing -> path {
    $root | path join $PARTICLES_DIR
}

# Extension a store filename may carry after the CID: dot-separated
# alphanumeric segments ("md", "tar.gz"), no leading dot. One canon for the
# write side (`particle-store --ext` validates against it) and the read side
# (`particle-files` recognizes store files by it).
export const PARTICLE_EXT_RE = '^[A-Za-z0-9]+(\.[A-Za-z0-9]+)*$'

# <root>/particles/<cid> — one file, self-addressed by the CID v0 of its
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

# What marks a file in receipts/ as a receipt rather than its frozen proof.
# `<cid>.receipt.cert.json` deliberately does not end with it.
export const RECEIPT_SUFFIX = ".receipt.json"

# receipts/<author-cid>/<edge-cid>.receipt.json — the custody receipt's
# manifest path, relative to the graph root. Mirrors the link layout: the
# author directory plus the edge filename address the act as unambiguously as
# the cyberlink CID, and keying by the edge alone would collide the moment a
# second author's copy of the same edge lands. Relative because it doubles as
# the proof's leaf.filepath: a custody layer places the receipt at this same
# path inside the layer dir — which is also what binds the author to the
# receipt, since the path enters the seal's signed root.
export def receipt-relpath [author: string edge_cid: string]: nothing -> string {
    [$RECEIPTS_DIR $author $"($edge_cid)($RECEIPT_SUFFIX)"] | path join
}

# The edge CID a receipt file is named after — the filename half of
# receipt-relpath's inverse (the author half is the parent directory).
# `seal` spelled it inline three times as `str replace ".receipt.json" ""`,
# which is this module's rule read backwards in a file that does not own it.
# Cut by length rather than replaced: the suffix comes off the END, where
# `str replace` without --regex took the first match anywhere in the name.
#
# The refusal is what a length cut needs and a replace did not: handed a name
# that is not a receipt, `str replace` gave the name back unchanged, while
# cutting blind returns a truncation — `Qm123.receipt.cert.json` came back as
# `Qm123.rece`, a plausible-looking string that is nobody's CID. Every caller
# today filters by the same suffix first, so this never fires; it fires for the
# caller who does not.
export def receipt-cid [file: path]: nothing -> string {
    let base = $file | path basename
    if not ($base | str ends-with $RECEIPT_SUFFIX) {
        error make {msg: $"not a receipt filename: ($base) — expected <cid>($RECEIPT_SUFFIX)"}
    }
    $base | str substring ..<(-1 * ($RECEIPT_SUFFIX | str length))
}

# Every custody receipt in the graph home, with the two halves of its
# address read off the path — the act's author (directory name) and the edge
# CID (filename) — link-files' twin over receipts/.
export def receipt-files [root: path]: nothing -> table {
    list-dirs (receipts-dir $root)
    | where ($it | path basename) =~ $CID_V0_RE
    | each {|d|
        list-files $d --suffix $RECEIPT_SUFFIX
        | each {|f| {file: $f author: ($d | path basename) edge: (receipt-cid $f)} }
    }
    | flatten
}

# <edge-cid>.receipt.cert.json — the frozen receipt proof, also at a layer's
# root. The bare edge is enough inside a bundle: it carries exactly one act.
export def receipt-cert-filename [edge_cid: string]: nothing -> string {
    $"($edge_cid).receipt.cert.json"
}

# <root>/receipts/<author>/<edge-cid>.receipt.cert.json — frozen beside the
# receipt it proves, in the same author directory.
export def receipt-cert-path [root: path author: string edge_cid: string]: nothing -> path {
    receipts-dir $root | path join $author (receipt-cert-filename $edge_cid)
}

# <bundle>/custody — the appended custody layers of a re-exported bundle
export def custody-dir [bundle: path]: nothing -> path {
    $bundle | path join $CUSTODY_DIR
}

# custody/<index>-<signer-cid-prefix> — one custody layer. The index makes the
# intended order readable; verification enforces it against the receipt chain,
# so a renamed or renumbered layer fails instead of lying silently.
export def custody-layer-dirname [index: int signer_cid: string]: nothing -> string {
    $"($index)-($signer_cid | str substring 0..11)"
}

# <edge-cid>.handoff.json — the sender's signed handoff, at the root of the
# proof dir it leaves from: the bundle root for the author, the sender's
# custody layer for a custodian. Named by the edge, like every file at a
# bundle's root — one act per bundle, so the bare edge is unambiguous; the
# act's full identity stays in the handoff's own `link` field.
export def handoff-filename [edge_cid: string]: nothing -> string {
    $"($edge_cid).handoff.json"
}

# <edge-cid>.cert.json — the certificate filename, also used at a bundle's root
export def cert-filename [edge_cid: string]: nothing -> string {
    $"($edge_cid).cert.json"
}

# <root>/<signer>/<edge-cid>.json — the link: pair in the file, signer in the
# path. The whole path is the cyberlink; the file alone is only the edge.
export def link-path [root: path signer: string edge_cid: string]: nothing -> path {
    signer-dir $root $signer | path join $"($edge_cid).json"
}

# <root>/certs/<signer>/<edge-cid>.cert.json — the frozen birth certificate;
# certs mirror the link layout, one signer directory each.
export def cert-path [root: path signer: string edge_cid: string]: nothing -> path {
    certs-dir $root | path join $signer (cert-filename $edge_cid)
}

# Every link file in the graph home, with the two halves of its address read
# off the path: the signer (directory name) and the edge CID (filename stem).
# The one definition of the walk, so seal's catalogue and a reading cannot
# disagree about which files are the graph's links.
export def link-files [root: path]: nothing -> table {
    signer-dirs $root
    | each {|d|
        list-files $d --suffix ".json"
        | each {|f| {file: $f signer: ($d | path basename) edge: ($f | path parse | get stem)} }
    }
    | flatten
}

# Every imported bundle carrying this edge: imported/<signer>/<edge-cid>/,
# one existence check per signer directory — the imported/ tree mirrors the
# graph layout, signer above, edge below.
# A walk by listing, never `glob (… | path join * $cid)` — the graph path is
# spliced into that pattern, so a `[` in it returns [] and the caller reads
# "unknown edge" for a copy sitting right there.
export def imported-edge-copies [root: path edge_cid: string]: nothing -> table {
    list-dirs (imported-dir $root)
    | where (($it | path join $edge_cid) | path exists)
    | each {|sd| {dir: ($sd | path join $edge_cid) signer: ($sd | path basename)} }
}

# <root>/seals/<root-hex-12> — the 12-char truncation is a layout contract:
# seal writes the snapshot there, bundle looks it up by the certificate's root.
export def snapshot-dir [root: path root_hex: string]: nothing -> path {
    seals-dir $root | path join ($root_hex | str substring 0..11)
}
