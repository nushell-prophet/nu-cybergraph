# Bootstrap a neuron repo: multiproof machinery + the cybergraph directories.

use _repo.nu [repo-root graph-root]
use _deps.nu [init]

# `init` here is nu-multiproof's init (pubkey registration in
# multiproofs/pubkeys/); this wrapper adds the cybergraph layout on top.
export def main [
    --repo: path # Target git repo root (default: git root of current directory)
    --pubkey: path # SSH public key to register (default: signing key from git config)
] {
    # Nested always: the graph lives in <repo>/cybergraph/, one service dir
    # in an arbitrary-shaped repo. Root layout (graph = whole repo, as in
    # this repo itself) is still honored by graph-root discovery — it just
    # isn't something init creates.
    mkdir ((repo-root $repo) | path join cybergraph)
    let root = graph-root $repo
    if $pubkey != null {
        init --repo $root --pubkey $pubkey
    } else {
        init --repo $root
    }
    mkdir ($root | path join links) ($root | path join certs)
    print $"cybergraph layout ready: links/ certs/ in ($root)"
}
