# The particle store primitive and the text-or-CID resolver shared by every
# write command (`particle add`, `link add`, the convention verbs). Borrowed
# discipline: cy's `pin-text` — the argument convention that made that CLI
# comfortable: a CID passes through untouched, anything else becomes a
# particle first.

use _layout.nu [particles-dir particle-path]
use _record.nu [CID_V0_RE]
use _deps/cid-v0.nu [cid-v0]

# Store bytes as particles/<cid> and return the CID. Idempotent: same bytes =
# same CID = same file, so an already-present file is left untouched rather
# than rewritten. Stores the exact bytes given — no newline appended, no
# encoding transform — so the file trivially self-addresses.
export def particle-store [root: path]: binary -> string {
    let bytes = $in
    let cid = $bytes | cid-v0
    mkdir (particles-dir $root)
    let out = particle-path $root $cid
    if not ($out | path exists) {
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
