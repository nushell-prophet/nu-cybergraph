# The particle store primitive and the text-or-CID resolver shared by every write
# command (`particle add`, `link add`, the convention verbs). Borrowed
# discipline: cy's `pin-text` — the argument convention that made that CLI
# comfortable: a CID passes through untouched, anything else becomes a file
# first.

use _layout.nu [particles-dir particle-path PARTICLE_EXT_RE]
use _validate.nu [CID_V0_RE]
use _fs.nu list-files
use _deps/cid-v0.nu [cid-v0]

# The store grouped by address: {<cid>: [<path> …]} from one directory
# listing. The one definition of the store's filename rule — `<cid>` bare or
# `<cid>.<ext>`, the extension being a name and not part of the address.
# Why an index and not a per-lookup scan: a reading walks the whole graph and
# dereferences both ends of every link, so a scan per lookup made `link list`
# quadratic in the store (43s over 567 links). A single lookup still costs one
# listing, exactly what it cost before.
export def store-index [root: path]: nothing -> record {
    list-files (particles-dir $root) | reduce --fold {} {|p acc|
        let cid = store-cid $p
        if $cid == null {
            $acc
        } else {
            $acc | upsert $cid (($acc | get --optional $cid | default []) ++ [$p])
        }
    }
}

# The address a store filename claims — `<cid>` or `<cid>.<ext>` — or null when
# the name is not a store file at all. The one place that rule is spelled out,
# so the index and a reader sorting search hits cannot disagree about what
# belongs to the store.
export def store-cid [file: path]: nothing -> any {
    let base = $file | path basename
    let cid = $base | split row "." | first
    if $cid !~ $CID_V0_RE { return null }
    let ext = $base | str substring (($cid | str length) + 1)..
    if ($base != $cid) and ($ext !~ $PARTICLE_EXT_RE) { return null }
    $cid
}

# All store files addressing a CID: `<cid>` bare or `<cid>.<ext>`. The store
# invariant is at most one such file (`particle-store` keeps it); readers
# fail fast on a violation instead of picking one copy silently.
export def particle-files [root: path cid: string]: nothing -> list<string> {
    store-index $root | get --optional $cid | default []
}

# Resolve a CID to its one store file within an already-built index.
# `--optional` returns null for a CID the store holds no file for — the one
# absence a reader may legitimately meet, because a cyberlink names CIDs and
# the bytes need not be local. An ambiguous store still fails under it: two
# files for one CID is a broken store, not an absence.
# Why `nothing -> any` and not `path`: nushell rejects a null return against a
# declared `path` at parse time.
export def index-find [index: record cid: string --optional]: nothing -> any {
    let files = $index | get --optional $cid | default []
    match ($files | length) {
        0 => { if $optional { null } else { error make {msg: $"no file ($cid) in store"} } }
        1 => { $files | first }
        _ => { error make {msg: $"ambiguous store: ($files | length) files for ($cid) — one CID, one file"} }
    }
}

# The same resolution for a caller holding no index — one lookup, one listing.
export def particle-find [root: path cid: string --optional]: nothing -> any {
    index-find (store-index $root) $cid --optional=$optional
}

# A stored file's exact bytes, checked against the CID that names them. The one
# definition of the read-side self-address check: `particle cat` and the graph
# reader (_read.nu) both come through here, so a tampered file fails the same
# way whether a human or a query met it.
export def particle-verify [file: path cid: string]: nothing -> any {
    let content = open --raw $file
    if ($content | into binary | cid-v0) != $cid {
        error make {msg: $"tampered file: ($file | path basename) does not hash to its name"}
    }
    $content
}

# Find and read in one call, for a caller holding no index. `--optional`
# forwards to particle-find — absence returns null, tampering still raises.
export def particle-read [root: path cid: string --optional]: nothing -> any {
    let file = particle-find $root $cid --optional=$optional
    if $file == null { return null }
    particle-verify $file $cid
}

# Store bytes as particles/<cid> and return the CID. Idempotent: same bytes =
# same CID = same file, so an already-present file is left untouched rather
# than rewritten. Stores the exact bytes given — no newline appended, no
# encoding transform — so the file trivially self-addresses.
# `--ext` names the file `<cid>.<ext>` — a presentation hint, not part of the
# address: if the content already exists under any name, the existing file
# wins and no second copy is written (one CID, one file).
export def particle-store [root: path --ext: string]: binary -> string {
    let bytes = $in
    if $ext != null and $ext !~ $PARTICLE_EXT_RE {
        error make {msg: $"malformed particle extension: ($ext) — expected dot-separated alphanumeric segments, e.g. md"}
    }
    let cid = $bytes | cid-v0
    if (particle-files $root $cid | is-empty) {
        mkdir (particles-dir $root)
        # No null guard around the forward: nushell refuses `--ext null` only
        # when the PARSER can prove the value is nothing (a `null` literal or a
        # variable it typed as such). A flag's own value is not that case — it
        # forwards fine and arrives absent, which is exactly what a missing
        # --ext means. Same everywhere this module forwards an optional flag.
        $bytes | save --raw (particle-path $root $cid --ext $ext)
    }
    $cid
}

# Whether a string names something on disk right now — `--no-symlink` so a
# broken symlink (a real file on disk, however dead its target) still counts;
# opening it below is what turns the missing target into a loud error.
def path-exists-here [arg: string]: nothing -> bool {
    $arg | path exists --no-symlink
}

# Whether a string reads as a path even though nothing lives there right now:
# a directory separator, a dot-extension, or a dotfile name (`.env`,
# `.gitignore` — no extension by `path parse`'s own reckoning, since it
# treats the leading dot as the whole stem). The signal that a caller almost
# certainly meant a file and mistyped it, not that the string is meant as
# content — literal cyberlink content (a thesis, an argument, a question)
# all but never starts with a dot or contains a separator.
def looks-path-shaped [arg: string]: nothing -> bool {
    ($arg =~ '[/\\]') or (($arg | path parse | get extension) != "") or ($arg | str starts-with '.')
}

# Resolve a string argument to the bytes it should publish. An existing path
# is opened and its bytes returned — the common case, since a bare-argument
# caller who writes a path all but always means "publish this file", not
# "publish this path string". A path-shaped string that names nothing is
# refused loudly: falling through to literal content would silently publish
# a typo instead of catching it. `--literal` skips all of this and always
# takes the string itself as content — the escape hatch for the one
# legitimate case, a path string meant as content.
#
# The shared footgun check behind `particle add`'s positional argument and
# `resolve-particle`'s text-or-CID argument: both take a plain string
# argument, so without this a path string is stored as the path text, not
# the bytes it names.
export def resolve-arg-bytes [arg: string --literal]: nothing -> binary {
    if $literal {
        return ($arg | into binary)
    }
    if (path-exists-here $arg) {
        open --raw $arg | into binary
    } else if (looks-path-shaped $arg) {
        error make {msg: $"($arg) looks like a path, but nothing exists there — check the path, or pass --literal to publish the string itself as content"}
    } else {
        $arg | into binary
    }
}

# Resolve a text-or-CID argument: a CID v0 is checked against this repo's own
# store before being used as-is; any other string is resolved to bytes (see
# `resolve-arg-bytes` — a path is opened, anything else is literal) and
# published as a file, replaced by its CID (so it is always local the moment
# this returns). Content that itself looks like a CID cannot pass through
# here as content — publish it with `particle add` first and hand over the
# returned CID.
# Not an --ignore-cid flag (cy's escape hatch) because: `particle add` composes
# to the same result, and one uniform rule beats a flag on every write command.
#
# `index` comes from the caller rather than being built here: a write can
# resolve several arguments (link add's two endpoints, a convention's nested
# operands), and this is the same store-index/index-find split `_read.nu`
# already draws for reads — a scan per lookup was measured quadratic there
# (43s over 567 links), and the write side walks the same particles/ dir.
# One index per top-level write call, reused across every argument it
# resolves.
#
# --allow-missing skips the local-file check on a CID argument. Without it, a
# CID this repo holds no file for is refused: most of the time that CID is a
# typo or a wrong copy-paste, and nothing about content-addressing can tell a
# typo from a real reference to bytes held elsewhere — the two look identical
# until something dereferences them, which may be never. Refusing by default
# catches the common case at the point of the mistake; --allow-missing is the
# escape hatch for the legitimate one, a forward reference to bytes this repo
# does not (yet) hold.
export def resolve-particle [root: path index: record arg: string --allow-missing --literal]: nothing -> string {
    if $arg =~ $CID_V0_RE {
        if not $allow_missing and (index-find $index $arg --optional) == null {
            error make {msg: $"no local file for ($arg) — pass --allow-missing to reference a CID this repo does not hold bytes for"}
        }
        return $arg
    }
    (resolve-arg-bytes $arg --literal=$literal) | particle-store $root
}
