# Publish particles: arbitrary bytes stored self-addressed under particles/. The
# public face of the store primitive every write command resolves its text
# arguments through.

use _repo.nu graph-root
use _particle.nu [particle-store particle-read resolve-arg-bytes]
use _validate.nu [CID_V0_RE]

# Publish content as a self-addressed file under particles/ and return its
# CID. Content comes as the argument or through the pipeline (string or raw
# bytes). Idempotent: identical content is one file. Also the escape hatch
# for content that looks like a CID: `particle add` never treats its input
# as an address.
#
# The argument form opens a string that names an existing local path and
# publishes its bytes — most bare-argument callers who write a path mean
# "publish this file", not "publish this path string" (see resolve-arg-bytes
# for the full three-way rule, including the loud error on a path-shaped
# argument that names nothing). `--literal` is the escape hatch for a path
# string meant as content. Piping is unaffected either way: piped content is
# always literal, even when it happens to be path-shaped — the pipe is
# itself the deliberate-intent signal.
@example "publish text as a particle" { particle add "cyber" }
@example "publish a file's bytes" { particle add path/to/doc.md }
@example "publish a path string itself, not the file it names" { particle add path/to/doc.md --literal }
@example "publish markdown, keep the extension" { particle add path/to/doc.md --ext md }
export def add [
    content?: string # content to publish, or a path to open and publish; omit to pipe content in
    --repo: path # Target repo root (default: git root of current directory)
    --ext: string # filename extension for the store file (e.g. md); the address stays the bare CID
    --literal # treat the argument as literal content even if it names a path
]: [nothing -> string, string -> string, binary -> string] {
    let piped = $in
    let root = graph-root $repo
    if $content != null and $piped != null {
        error make {msg: "content given both as an argument and by pipeline — pass one"}
    }
    let bytes = if $content != null {
        resolve-arg-bytes $content --literal=$literal
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
