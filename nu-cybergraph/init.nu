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
]: nothing -> nothing {
    # The graph always lives in <repo>/cybergraph/ — one service dir in an
    # arbitrary-shaped repo (see graph-root).
    mkdir ((repo-root $repo) | path join cybergraph)
    let root = graph-root $repo
    let pubkeys_dir = $root | path join multiproofs pubkeys
    let before = list-files $pubkeys_dir --suffix ".pub"
    init --repo $root --pubkey $pubkey
    let after = list-files $pubkeys_dir --suffix ".pub"

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
    if ($after | is-empty) {
        error make {msg: "no signer registered: set `git config user.signingKey <key>` or pass `--pubkey` — `init` establishes the signer identity, and a graph home without one cannot take a link"}
    }

    # And refuse a run that established a SECOND signer. Upstream's registration
    # is additive — a key whose fingerprint names no file yet is written beside
    # whatever is already there — so pointing `user.signingKey` at another key
    # and re-running `init` used to print `Registered` and exit clean over a
    # trust list holding two. That state is the one every write command then
    # refuses (`_signer.nu`: several registered keys is an error, never a pick),
    # so the run would have left a home that cannot take a link while saying it
    # was ready — the same loop the empty-list check above exists to close.
    #
    # Undone rather than reported and left: identity is established here, so a
    # run that establishes the wrong thing has to put it back. Only what THIS
    # run added — a home that already held several keys was broken before this
    # command ran, and deleting a key nobody asked about is not `init`'s call.
    if (($after | length) > 1) {
        let added = $after | where {|f| $f not-in $before }
        for f in $added { rm $f }
        error make {
            msg: (
                [
                    $"multiple pubkeys registered in ($pubkeys_dir | path relative-to $root) \(($after | length)) — a graph home has exactly one signer identity"
                    (if ($added | is-empty) {
                        "none of them was registered by this run: remove all but one by hand"
                    } else {
                        $"the key this run registered was removed again: ($added | each { path basename } | str join ', ')"
                    })
                    "a second signer needs its own graph home"
                ] | str join "\n"
            )
        }
    }

    mkdir (links-dir $root) (certs-dir $root)
    print $"cybergraph layout ready: links/ certs/ in ($root)"
}
