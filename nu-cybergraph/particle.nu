# Publish files: arbitrary bytes stored self-addressed under particles/. The
# public face of the store primitive every write command resolves its text
# arguments through.

use _repo.nu graph-root
use _particle.nu [particle-store particle-read]
use _validate.nu [CID_V0_RE]

# Publish content as a self-addressed file under particles/ and return its
# CID. Content comes as the argument or through the pipeline (string or raw
# bytes — `open --raw file | particle add` publishes a file). Idempotent:
# identical content is one file. Also the escape hatch for content that
# looks like a CID: `particle add` never treats its input as an address.
@example "publish text as a file" { particle add "cyber" }
@example "publish a file's bytes" { open --raw doc.md | particle add }
@example "publish markdown, keep the extension" { open --raw doc.md | particle add --ext md }
export def add [
    content?: string # content to publish; omit to pipe content in
    --repo: path # Target repo root (default: git root of current directory)
    --ext: string # filename extension for the store file (e.g. md); the address stays the bare CID
]: [nothing -> string, string -> string, binary -> string] {
    let piped = $in
    let root = graph-root $repo
    if $content != null and $piped != null {
        error make {msg: "content given both as an argument and by pipeline — pass one"}
    }
    let bytes = if $content != null {
        $content | into binary
    } else if $piped != null {
        $piped | into binary
    } else {
        error make {msg: "nothing to publish — pass a string argument or pipe content in"}
    }
    $bytes | particle-store $root --ext $ext
}

# Read a stored file's exact bytes by CID. The argument is the bare 46-char
# CID — never a filename or path — and the file is found whatever extension it
# carries. The bytes are verified to hash back to the CID before being
# returned, so a tampered store file fails instead of being served.
# Named cat after `ipfs cat` — the established verb for reading by CID.
# Not `get` because: the name would collide with the builtin `get` for
# star-importers. That is workable (skip `use particle.nu *`, or alias the
# builtin first), but cat carries the domain meaning, so the collision is
# not worth managing.
#
# Why `--optional` rather than a separate `particle has`: a reader walking a
# graph has to tell "the bytes are not local" from "the bytes are tampered",
# and those are the same outcome under a bare `try`/`catch` — the catch
# swallows the tamper error, which is the one thing the hash check exists to
# raise. A predicate plus a read would split that into two calls with a gap
# between them; one call answers both.
@example "read a stored file" { particle cat QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV }
@example "read it, or null if this repo does not hold it" { particle cat QmQXup… --optional }
export def cat [
    cid: string # CID v0 of the file (Qm + 44 chars)
    --repo: path # Target repo root (default: git root of current directory)
    --optional # return null when the store holds no file for this CID, instead of failing
]: nothing -> any {
    if $cid !~ $CID_V0_RE {
        error make {msg: $"not a CID v0: ($cid) — particle cat takes the bare 46-char CID, not a filename"}
    }
    particle-read (graph-root $repo) $cid --optional=$optional
}
