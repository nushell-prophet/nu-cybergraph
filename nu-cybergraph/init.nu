# Bootstrap a signer's repo: multiproof machinery + the cybergraph directories.

use _repo.nu [repo-root graph-root]
use _layout.nu [links-dir certs-dir]
use _fs.nu [list-files]
use _deps/init.nu [init]

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
    init --repo $root --pubkey $pubkey

    # Refuse a run that established no signer. With neither --pubkey nor a git
    # `user.signingKey`, upstream's resolve-key prints two advisory lines and
    # returns null; this command then used to report the layout ready over an
    # empty trust list. The failure surfaced at the first write instead, as
    # `no pubkey registered — run nu-cybergraph init first` — naming the
    # command that had just said it was ready, a loop with no exit for an
    # operator who has not heard of --pubkey.
    #
    # Checked here because this is where identity is established: `init`'s own
    # job, in its own words, and the reason `seal` refuses to register as a
    # side effect. `list-files` and not `glob`: a repo path is data and may
    # hold glob metacharacters.
    if (list-files ($root | path join multiproofs pubkeys) --suffix ".pub" | is-empty) {
        error make {msg: "no signer registered: set `git config user.signingKey <key>` or pass `--pubkey` — `init` establishes the signer identity, and a graph home without one cannot take a link"}
    }

    mkdir (links-dir $root) (certs-dir $root)
    print $"cybergraph layout ready: links/ certs/ in ($root)"
}
