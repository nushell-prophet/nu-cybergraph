# Publish content particles: arbitrary bytes stored self-addressed under
# particles/. The public face of the store primitive every write command
# resolves its text arguments through.

use _repo.nu graph-root
use _particle.nu [particle-store]

# Publish content as a self-addressed particle under particles/ and return its
# CID. Content comes as the argument or through the pipeline (string or raw
# bytes — `open --raw file | particle add` publishes a file). Idempotent:
# identical content is one particle. Also the escape hatch for content that
# looks like a CID: `particle add` never treats its input as an address.
@example "publish a text particle" { particle add "cyber" }
@example "publish a file's bytes" { open --raw doc.md | particle add }
export def add [
    content?: string # content to publish; omit to pipe content in
    --repo: path # Target repo root (default: git root of current directory)
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
    $bytes | particle-store $root
}
