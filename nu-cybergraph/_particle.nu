# The file store primitive and the text-or-CID resolver shared by every write
# command (`particle add`, `link add`, the convention verbs). Borrowed
# discipline: cy's `pin-text` — the argument convention that made that CLI
# comfortable: a CID passes through untouched, anything else becomes a file
# first.

use _layout.nu [particles-dir particle-path PARTICLE_EXT_RE]
use _validate.nu [CID_V0_RE]
use _deps/cid-v0.nu [cid-v0]

# All store files addressing a CID: `<cid>` bare or `<cid>.<ext>`. The store
# invariant is at most one such file (`particle-store` keeps it); readers
# fail fast on a violation instead of picking one copy silently.
export def particle-files [root: path cid: string]: nothing -> list<string> {
    let dir = particles-dir $root
    if not ($dir | path exists) { return [] }
    ls $dir | get name | where {|p|
        let base = $p | path basename
        let rest = $base | str substring ($cid | str length)..
        ($base | str starts-with $cid) and (
            $rest == "" or (($rest | str starts-with ".") and (($rest | str substring 1..) =~ $PARTICLE_EXT_RE))
        )
    }
}

# Resolve a CID to its one store file, whatever extension it carries.
# `--optional` returns null for a CID the store holds no file for — the one
# absence a reader may legitimately meet, because a cyberlink names CIDs and
# the bytes need not be local. An ambiguous store still fails under it: two
# files for one CID is a broken store, not an absence.
# Why `nothing -> any` and not `path`: nushell rejects a null return against a
# declared `path` at parse time.
export def particle-find [root: path cid: string --optional]: nothing -> any {
    let files = particle-files $root $cid
    match ($files | length) {
        0 => { if $optional { null } else { error make {msg: $"no file ($cid) in store"} } }
        1 => { $files | first }
        _ => { error make {msg: $"ambiguous store: ($files | length) files for ($cid) — one CID, one file"} }
    }
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

# Resolve a text-or-CID argument: a CID v0 is used as-is; any other string is
# published as a file and replaced by its CID. Content that itself looks like
# a CID cannot pass through here as content — publish it with `particle add`
# first and hand over the returned CID.
# Not an --ignore-cid flag (cy's escape hatch) because: `particle add` composes
# to the same result, and one uniform rule beats a flag on every write command.
export def resolve-particle [root: path arg: string]: nothing -> string {
    if $arg =~ $CID_V0_RE { return $arg }
    $arg | into binary | particle-store $root
}
