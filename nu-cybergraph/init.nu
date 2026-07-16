# Bootstrap a neuron repo: multiproof machinery + the cybergraph directories.

use _repo.nu [repo-root graph-root]
use _deps.nu [init]

# `init` here is nu-multiproof's init (pubkey registration in
# multiproofs/pubkeys/); this wrapper adds the cybergraph layout on top.
export def main [
    --repo: path # Target git repo root (default: git root of current directory)
    --pubkey: path # SSH public key to register (default: signing key from git config)
] {
    let base = repo-root $repo
    # Nested by default: the graph lives in <repo>/cybergraph/, one service
    # dir in an arbitrary-shaped repo. Guard: a repo already carrying a
    # root-layout graph keeps it — re-running init must never split an
    # existing graph into a second home.
    if not (($base | path join multiproofs) | path exists) {
        mkdir ($base | path join cybergraph)
    }
    let root = graph-root $repo
    if $pubkey != null {
        init --repo $root --pubkey $pubkey
    } else {
        init --repo $root
    }
    mkdir ($root | path join links) ($root | path join certs)
    print $"cybergraph layout ready: links/ certs/ in ($root)"
}
