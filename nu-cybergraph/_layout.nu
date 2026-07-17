# Filesystem layout of the cybergraph home. One source of truth for every
# path the module reads or writes under the graph root — same lesson as
# nu-multiproof's _layout.nu: a layout change is one edit here, not six files
# silently disagreeing. Paths into multiproofs/ stay inline at call sites —
# they pin nu-multiproof's public layout, not ours.

export const LINKS_DIR = "links"
export const CERTS_DIR = "certs"
export const SEALS_DIR = "seals"
export const EXPORTS_DIR = "exports"
export const IMPORTED_DIR = "imported"

# <root>/links
export def links-dir [root: path]: nothing -> path {
    $root | path join $LINKS_DIR
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
