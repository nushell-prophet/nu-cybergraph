# Publish content particles: arbitrary bytes stored self-addressed under
# particles/. The public face of the store primitive every write command
# resolves its text arguments through.

use _repo.nu graph-root
use _particle.nu [particle-store particle-find]
use _record.nu [CID_V0_RE]
use _deps/cid-v0.nu [cid-v0]

# Publish content as a self-addressed particle under particles/ and return its
# CID. Content comes as the argument or through the pipeline (string or raw
# bytes — `open --raw file | particle add` publishes a file). Idempotent:
# identical content is one particle. Also the escape hatch for content that
# looks like a CID: `particle add` never treats its input as an address.
@example "publish a text particle" { particle add "cyber" }
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
    if $ext == null {
        $bytes | particle-store $root
    } else {
        $bytes | particle-store $root --ext $ext
    }
}

# Read a particle's exact bytes by CID. The argument is the bare 46-char CID —
# never a filename or path — and the store file is found whatever extension it
# carries. The bytes are verified to hash back to the CID before being
# returned, so a tampered store file fails instead of being served.
# Named cat after `ipfs cat` — the established verb for reading by CID.
# Not `get` because: the name would collide with the builtin `get` for
# star-importers. That is workable (skip `use particle.nu *`, or alias the
# builtin first), but cat carries the domain meaning, so the collision is
# not worth managing.
@example "read a particle" { particle cat QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV }
export def cat [
    cid: string # CID v0 of the particle (Qm + 44 chars)
    --repo: path # Target repo root (default: git root of current directory)
]: nothing -> any {
    if $cid !~ $CID_V0_RE {
        error make {msg: $"not a CID v0: ($cid) — particle cat takes the bare 46-char CID, not a filename"}
    }
    let file = particle-find (graph-root $repo) $cid
    let content = open --raw $file
    if ($content | into binary | cid-v0) != $cid {
        error make {msg: $"tampered particle: ($file | path basename) does not hash to its name"}
    }
    $content
}
