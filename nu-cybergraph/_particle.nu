# The particle store primitive and the text-or-CID resolver shared by every
# write command (`particle add`, `link add`, the convention verbs). Borrowed
# discipline: cy's `pin-text` — the argument convention that made that CLI
# comfortable: a CID passes through untouched, anything else becomes a
# particle first.

use _layout.nu [particles-dir particle-path PARTICLE_EXT_RE]
use _record.nu [CID_V0_RE]
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
export def particle-find [root: path cid: string]: nothing -> path {
    let files = particle-files $root $cid
    match ($files | length) {
        0 => { error make {msg: $"no particle ($cid) in store"} }
        1 => { $files | first }
        _ => { error make {msg: $"ambiguous store: ($files | length) files for ($cid) — one CID, one file"} }
    }
}

# Store bytes as particles/<cid> and return the CID. Idempotent: same bytes =
# same CID = same file, so an already-present file is left untouched rather
# than rewritten. Stores the exact bytes given — no newline appended, no
# encoding transform — so the file trivially self-addresses.
# `--ext` names the file `<cid>.<ext>` — a presentation hint, not part of the
# address: if the particle already exists under any name, the existing file
# wins and no second copy is written (one CID, one file).
export def particle-store [root: path --ext: string]: binary -> string {
    let bytes = $in
    if $ext != null and $ext !~ $PARTICLE_EXT_RE {
        error make {msg: $"malformed particle extension: ($ext) — expected dot-separated alphanumeric segments, e.g. md"}
    }
    let cid = $bytes | cid-v0
    if (particle-files $root $cid | is-empty) {
        mkdir (particles-dir $root)
        let out = if $ext == null {
            particle-path $root $cid
        } else {
            particle-path $root $cid --ext $ext
        }
        $bytes | save --raw $out
    }
    $cid
}

# Resolve a particle argument: a CID v0 is used as-is; any other string is
# published as a content particle and replaced by its CID. Content that itself
# looks like a CID cannot pass through here as content — publish it with
# `particle add` first and hand over the returned CID.
# Not an --ignore-cid flag (cy's escape hatch) because: `particle add` composes
# to the same result, and one uniform rule beats a flag on every write command.
export def resolve-particle [root: path arg: string]: nothing -> string {
    if $arg =~ $CID_V0_RE { return $arg }
    $arg | into binary | particle-store $root
}
