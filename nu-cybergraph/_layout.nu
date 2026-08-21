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

# nu-multiproof's directory inside the graph home. Named so the closed-set
# check can recognise it; every path INTO it stays inline at its call site,
# because those pin nu-multiproof's public layout and not ours.
export const MULTIPROOFS_DIR = "multiproofs"

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

# <root>/particles — the particle store, every file self-addressed: content
# published by `particle add` or by a text argument to a write command, and
# instruction and address records published so a reader can dereference an
# instruction edge (bj002 "Reading instructions"). A record lands here because
# a writer put it there — a convention minting it, or `particle add-edge` /
# `particle add-link` before a plain link names it — never because a command
# derived it as a side effect.
# Not in the seal manifest: a stored file is anchored the moment a sealed link names
# its CID (README "Graph home").
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

# The address a store filename claims — `<cid>` or `<cid>.<ext>` — or null when
# the name is not a store file at all. The one place that rule is spelled out,
# so the index and a reader sorting search hits cannot disagree about what
# belongs to the store.
#
# It lives here and not in `_particle.nu`, where it was written, because it is
# the read half of `particle-path` directly above: one rule, both directions,
# in the module that owns every other path under the graph home. The move is
# also what lets `strays` apply it — `_particle.nu` imports this module, so
# reaching the other way would close an import cycle.
export def store-cid [file: path]: nothing -> any {
    let base = $file | path basename
    let cid = $base | split row "." | first
    if $cid !~ $CID_V0_RE { return null }
    let ext = $base | str substring (($cid | str length) + 1)..
    if ($base != $cid) and ($ext !~ $PARTICLE_EXT_RE) { return null }
    $cid
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
# act's full identity is spelled out inside, as `cid_from`, `cid_to` and
# `signer` (_handoff.nu). v1 carried it as one derived CID in a `link` field.
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
#
# No closed-set guard here, and the reason is worth keeping: `link imported`
# hands this function a BUNDLE directory, which shares the signer layout but is
# not a graph home — it carries a certificate, a handoff and its own store
# beside the signer directories. The guard belongs where a graph home is named,
# which is `_repo.nu graph-root`, and a bundle path never goes through it.
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

# --- the closed set ---
#
# SPEC section 3 draws the whole tree the graph home may hold. Until now that
# tree was prose; below it is a check. The rule the user chose is fully closed:
# a `README.md` or a `.gitignore` at the graph root is refused too, because a
# seal signs whatever is committed there, and anything written by hand belongs
# beside the graph home rather than inside it.
#
# `multiproofs/` is recognised here and walked nowhere. It sits inside the
# graph home, so a check that did not name it would call the proof layer a
# stray — but it is nu-multiproof's directory, with its own layout and its own
# churn per seal, and policing another project's tree is how the two repos
# start disagreeing about it. Naming it is not owning it: this module still
# builds no path into it, which is what the header says and why the constant
# below is a bare name rather than a `multiproofs-dir` function.

# The reserved directory names at the top of the graph home. Everything else up
# there must be a signer directory, told by its CID v0 form — the same
# distinction `signer-dirs` makes, written once as a list so the walk and the
# refusal cannot drift apart.
export const RESERVED_DIRS = [
    $PARTICLES_DIR $CERTS_DIR $SEALS_DIR $EXPORTS_DIR $IMPORTED_DIR $RECEIPTS_DIR $MULTIPROOFS_DIR
]

# A seal snapshot directory: the 12-char truncation `snapshot-dir` writes.
export const SNAPSHOT_RE = '^[0-9a-f]{12}$'

# What a certificate filename carries after the edge CID.
const CERT_SUFFIX = ".cert.json"

# What each directory may hold, in words. The `allowed` column is the recovery
# instruction, so it is written out rather than derived from the constants
# above: the operator reading the row needs the rule, not the name of the check
# that produced it.
const ALLOWS = {
    root: "the reserved directories (particles, certs, seals, exports, imported, receipts, multiproofs) and <signer-cid>/ directories"
    signer: "<edge-cid>.json link records"
    particles: "<cid> and <cid>.<ext> files"
    certs: "<signer-cid>/ directories"
    certs_signer: "<edge-cid>.cert.json certificates"
    seals: "<root-hex-12>/ snapshot directories"
    receipts: "<author-cid>/ directories"
    receipts_author: "<edge-cid>.receipt.json receipts and their .receipt.cert.json proofs"
    bundles: "<signer-cid>/ directories"
    bundles_signer: "<edge-cid>/ bundle directories"
}

# The edge CID a name in `certs/<signer>/` claims, or null when it is not a
# certificate filename at all.
def cert-name [file: path]: nothing -> any {
    named-after $file $CERT_SUFFIX
}

# The edge CID a name in `receipts/<author>/` claims — a receipt or the frozen
# proof beside it — or null when it is neither. `receipt-cid` refuses instead
# of answering, because its callers have already filtered by suffix; this is
# that filter.
def receipt-name [file: path]: nothing -> any {
    let receipt = named-after $file $RECEIPT_SUFFIX
    if $receipt != null { $receipt } else { named-after $file (receipt-cert-filename "") }
}

# `<cid><suffix>` -> the CID, or null. The shape every proof filename under the
# graph home shares, so the three rules above are one rule with three suffixes.
def named-after [file: path suffix: string]: nothing -> any {
    let base = $file | path basename
    if not ($base | str ends-with $suffix) { return null }
    let stem = $base | str substring ..<(-1 * ($suffix | str length))
    if $stem =~ $CID_V0_RE { $stem } else { null }
}

# Entries of $dir the layout does not describe. `keep` is handed each `ls` row
# and answers whether the tree admits it; everything else becomes a row.
#
# `ls --all`, because a dotfile is exactly the kind of thing this looks for.
def unexpected [dir: path allowed: string keep: closure]: nothing -> table {
    if not ($dir | path exists) { return [] }
    ls --all $dir
    | where {|e| not (do $keep $e) }
    | each {|e| {path: $e.name under: $dir allowed: $allowed} }
}

# Directories named by a CID v0, and nothing else — the shape `certs/`,
# `receipts/`, `exports/` and `imported/` all share one level down.
def cid-dirs-only [dir: path allowed: string]: nothing -> table {
    unexpected $dir $allowed {|e| $e.type == "dir" and ($e.name | path basename) =~ $CID_V0_RE }
}

# What sits at the top of the graph home that the tree does not name. Split out
# because two callers need exactly this and nothing deeper: `strays`, which
# continues downward, and `assert-known-home`, which must stay cheap enough to
# run on every read.
def top-strays [root: path]: nothing -> table {
    unexpected $root $ALLOWS.root {|e|
        let name = $e.name | path basename
        $e.type == "dir" and (($name in $RESERVED_DIRS) or ($name =~ $CID_V0_RE))
    }
}

# Every path under the graph home the layout does not describe, one row each:
# the path, the directory it sits in, and what that directory is allowed to
# hold — so the recovery is one obvious action and never a hunt.
#
# The walk stops where this repo's authority stops. Inside a seal snapshot are
# nu-multiproof's files; inside an export or an import is a bundle, a
# self-contained artifact `verify-bundle` checks as a whole. Naming their
# contents here would be this module asserting a layout it does not own, the
# same mistake as policing `multiproofs/`. Everything this module DOES name —
# the signer directories, the store, the certificates, the receipts — is
# walked to its leaves.
export def strays [root: path]: nothing -> table {
    if not ($root | path exists) { return [] }

    let particles = unexpected (particles-dir $root) $ALLOWS.particles {|e|
        $e.type != "dir" and (store-cid $e.name) != null
    }

    let links = signer-dirs $root | each {|d|
        unexpected $d $ALLOWS.signer {|e|
            let parsed = $e.name | path parse
            $e.type != "dir" and $parsed.extension == "json" and $parsed.stem =~ $CID_V0_RE
        }
    } | flatten

    let certs = list-dirs (certs-dir $root) | each {|d|
        unexpected $d $ALLOWS.certs_signer {|e| $e.type != "dir" and (cert-name $e.name) != null }
    } | flatten

    let receipts = list-dirs (receipts-dir $root) | each {|d|
        unexpected $d $ALLOWS.receipts_author {|e| $e.type != "dir" and (receipt-name $e.name) != null }
    } | flatten

    let bundles = [(exports-dir $root) (imported-dir $root)] | each {|top|
        list-dirs $top | each {|d| cid-dirs-only $d $ALLOWS.bundles_signer } | flatten
    } | flatten

    [
        (top-strays $root)
        $particles
        $links
        (cid-dirs-only (certs-dir $root) $ALLOWS.certs)
        $certs
        (unexpected (seals-dir $root) $ALLOWS.seals {|e|
            $e.type == "dir" and ($e.name | path basename) =~ $SNAPSHOT_RE
        })
        (cid-dirs-only (receipts-dir $root) $ALLOWS.receipts)
        $receipts
        (cid-dirs-only (exports-dir $root) $ALLOWS.bundles)
        (cid-dirs-only (imported-dir $root) $ALLOWS.bundles)
        $bundles
    ] | flatten
}

# Refuse a graph home this layout does not recognise, before a reader reports
# its emptiness as an answer.
#
# The failure this exists for: the link layout moved to
# `<signer-cid>/<edge-cid>.json`, and against a graph still in the old
# `links/<link-cid>.json` shape the readers answered `[]` at exit 0 — 301
# records read as none, with every count and tally built on that silently
# wrong. Worse, `seal` succeeded, signing a merkle root for a graph whose links
# it could not see and certifying none of them. A reader that finds nothing
# must fail rather than call it an empty graph.
#
# Only the top level, and that is the whole point: it is the level that says
# WHICH layout this is, and it costs one directory listing, so `graph-root` can
# call it on every command without turning `touching` — documented as costing
# the neighbourhood and not the graph — into a walk of the whole home. `strays`
# is the deep reading, and `seal` is where the deep rule is enforced.
export def assert-known-home [root: path]: nothing -> nothing {
    let foreign = top-strays $root
    if ($foreign | is-not-empty) {
        error make {msg: $"unknown graph home ($root): ($foreign | each {|r| $r.path | path basename } | str join ', ') — a graph home holds ($ALLOWS.root). A reader cannot tell a graph it does not understand from an empty one, so this refuses instead of answering nothing. A graph in the pre-signer-directory layout predates the current format and is not migrated: see the pre-1.0 note in CLAUDE.md"}
    }
}
