# Bootstrap a neuron repo: multiproof machinery + the cybergraph directories.

use _repo.nu [repo-root graph-root]
use _layout.nu [links-dir certs-dir]
use _deps.nu [init]

# `init` here is nu-multiproof's init (pubkey registration in
# multiproofs/pubkeys/); this wrapper adds the cybergraph layout on top.
export def main [
    --repo: path # Target git repo root (default: git root of current directory)
    --pubkey: path # SSH public key to register (default: signing key from git config)
] {
    # The graph always lives in <repo>/cybergraph/ — one service dir in an
    # arbitrary-shaped repo (see graph-root).
    mkdir ((repo-root $repo) | path join cybergraph)
    let root = graph-root $repo
    if $pubkey != null {
        init --repo $root --pubkey $pubkey
    } else {
        init --repo $root
    }
    mkdir (links-dir $root) (certs-dir $root)
    print $"cybergraph layout ready: links/ certs/ in ($root)"
}
