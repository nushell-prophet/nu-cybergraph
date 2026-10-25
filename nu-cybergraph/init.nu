# Bootstrap a signer's repo: multiproof machinery + the cybergraph directories.

use _repo.nu [ repo-root graph-root ]
use _layout.nu [ certs-dir ]
use _fs.nu [ list-files ]
use _deps/init.nu [ init ]

# Start a graph here: register the signer key and create cybergraph/ with certs/.
#
# `init` here is nu-multiproof's init (pubkey registration in
# multiproofs/pubkeys/); this wrapper adds the cybergraph layout on top.
@category cybergraph
export def main [
    --repo: path # Target repo root (default: the current directory; with --co-signer, the nearest dir holding cybergraph/, up to the git root)
    --pubkey: path # SSH public key to register (default: signing key from git config)
    --co-signer: path # SSH public key to add BESIDE the identity, without establishing one
]: nothing -> nothing {
    if $co_signer != null and $pubkey != null {
        error make {
            msg: "--pubkey and --co-signer are alternatives: --pubkey establishes the identity this graph writes under, --co-signer adds a key beside it"
            label: {text: "drop this or --pubkey" span: (metadata $co_signer).span}
        }
    }
    # The graph always lives in <repo>/cybergraph/ — one service dir in an
    # arbitrary-shaped repo (see graph-root).
    if $co_signer == null {
        mkdir ((repo-root $repo --init) | path join cybergraph)
    }
    let root = graph-root $repo
    let pubkeys_dir = $root | path join multiproofs pubkeys
    let before = list-files $pubkeys_dir --suffix ".pub"

    if $co_signer != null {
        return (add-co-signer $root $pubkeys_dir $before $co_signer)
    }
    init --repo $root --pubkey $pubkey
    let after = list-files $pubkeys_dir --suffix ".pub"

    # Refuse a run that established no signer. With neither --pubkey nor a git
    # `user.signingKey`, upstream's resolve-key prints two advisory lines and
    # returns null. Reporting the layout ready over an empty trust list would
    # push the failure to the first write, as `no pubkey registered — run
    # nu-cybergraph init first`, naming the command that had just said it was
    # ready: a loop with no exit for an operator who has not heard of --pubkey.
    #
    # Checked here because this is where identity is established: `init`'s own
    # job, in its own words, and the reason `seal` refuses to register as a
    # side effect. `list-files` and not `glob`: a repo path is data and may
    # hold glob metacharacters.
    if ($after | is-empty) {
        error make {msg: "no signer registered — `init` establishes the signer identity, and a graph home without one cannot take a link" help: "set `git config user.signingKey <key>` or pass `--pubkey`"}
    }

    # And refuse a run that added a key NOBODY ASKED FOR. Upstream's registration
    # is additive — a key whose fingerprint names no file yet is written beside
    # whatever is already there — so pointing `user.signingKey` at another key
    # and re-running `init` printed `Registered` and exited clean over a trust
    # list that had silently grown. A trust list is a statement about whose
    # signatures this graph accepts, so a key must never join it by accident.
    #
    # What this refusal is NOT, since `_signer.nu` stopped counting: a rule that
    # a graph home may hold only one key. It may hold several, and `--co-signer`
    # is how a second one is added on purpose. This branch is the accidental
    # route, and it stays closed.
    #
    # Undone rather than reported and left: identity is established here, so a
    # run that establishes the wrong thing has to put it back. Only what THIS
    # run added — a list that already held several keys is a `--co-signer` home
    # doing exactly what it should, and deleting a key nobody asked about is not
    # `init`'s call. Which is also why the test is growth and not size: a re-run
    # over a home with a co-signer registers nothing new and passes straight
    # through.
    if ($before | is-not-empty) and ($after | length) > ($before | length) {
        let added = $after | where $it not-in $before

        for f in $added { rm $f }
        error make {
            msg: (
                [
                    $"`init` registers the identity of ($pubkeys_dir | path relative-to $root) and does not grow its trust list — it holds ($before | length) already"
                    $"the key this run registered was removed again: ($added | path basename | str join ', ')"
                ] | str join "\n"
            )
            help: "to add a key beside the identity on purpose, pass --co-signer"
        }
    }

    # No signer directory made here: link files live in <signer-cid>/, and the
    # first `link add` creates it — git tracks no empty directory anyway.
    mkdir (certs-dir $root)
    print $"cybergraph layout ready: certs/ in ($root) — link files land in the signer's own <cid> directory at first add"
}

# Add a key to the trust list without establishing an identity: a co-signer
# signs the same seal root as the identity does, so a statement carries more
# than one signature and forging it costs every key that signed. Identity is
# unaffected — `_signer.nu` reads it from the key this checkout signs with, not
# from what the list holds.
#
# Upstream's `init --pubkey` IS the registration: it canonicalizes, refuses a
# private key (canonical rejects the multi-line form), names the file after the
# key's fingerprint and reports a key already registered. Reimplementing any of
# that here would enforce one rule in two places.
#
# Refused on an empty list, because the first key is not a co-signer: it would
# land as the only registered key while nothing established what it stands
# beside, and `--pubkey` is the flag that says that deliberately.
export def add-co-signer [root: path pubkeys_dir: path before: list<path> key: path]: nothing -> nothing {
    if ($before | is-empty) {
        error make {msg: "nothing to co-sign for: no pubkey is registered yet — a co-signer stands beside an identity" help: "run `nu-cybergraph init` (or `init --pubkey <key>.pub`) first"}
    }
    init --repo $root --pubkey $key
    let after = list-files $pubkeys_dir --suffix ".pub"

    print $"trust list: ($after | length) keys — the identity is still the key this checkout signs with"
}
