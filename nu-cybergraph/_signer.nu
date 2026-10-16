# This repo's own signer identity — the CID of the registered pubkey this
# checkout writes under.
#
# One definition, because it is one question: "who is this repo?" — the
# record's `signer` field and a receipt's custodian are the same answer, and a
# second copy of it is a fork waiting to drift, in the one place where a wrong
# answer signs a statement under the wrong name.
#
# The answer is NOT a count of `multiproofs/pubkeys/`. That directory is
# nu-multiproof's TRUST LIST — the keys whose signatures this repo accepts —
# and a second key belongs there on purpose: a co-signer adds its signature to
# a frozen seal snapshot, which is how one operator holding keys on several
# devices makes a statement expensive to forge (measured: two signatures under
# one root, `verify` still bound). Counting answers "who am I" with "whom do I
# trust", and a graph that gains a co-signer can then write no link at all.
#
# The identity is this checkout's own signing key — the same
# `user.signingKey` that `seal` signs the root with, so the key a record is
# authored under is the key whose signature catalogues it. It lives in
# `.git/config`, which a clone does not carry, so every device answers for
# itself and nothing has to be written down in the graph.
#
# Matched by key MATERIAL, never by a filename: `pubkey canonical` emits the
# exact bytes registration stores, so the local key's canonical form IS its
# registered file's content. `_verify-helpers.nu`'s `bound` records what a
# name-based match cost the one time one was tried.

use _fs.nu list-files
use _particle.nu [ particle-store ]
use _validate.nu [ CID_V0_RE ]
use _deps/cid-v0.nu [ cid-v0 ]
use _deps/pubkey.nu [ pubkey ]

# The canonical public bytes of a key named by a path. The `.pub` sibling wins:
# the path usually names the private half (it is what one signs with), while an
# identity is public material.
def key-pubkey [named: path]: nothing -> string {
    let expanded = $named | path expand
    let pub = if ($"($expanded).pub" | path exists) { $"($expanded).pub" } else { $expanded }

    if not ($pub | path exists) {
        # Why the fix is named: a linked worktree reads the main checkout's
        # config, so the path can be right on another machine — the same
        # message upstream's seal gives (nu-multiproof _key-helpers.nu).
        error make {msg: $"signing key not on this machine: ($named) — set user.signingKey to the key this graph writes under \(`git config user.signingKey <key>.pub`; in a linked worktree add --worktree, or the main checkout changes too\); the public half alone is enough with `seal --external-signer`"}
    }
    open --raw $pub | pubkey canonical
}

# The canonical public bytes of the key this call writes under.
#
# Duplicated from nu-multiproof's `init.nu` rather than imported: its
# `resolve-key` is private, and cross-repo imports of another project's
# _-internals carry no compatibility promise — the same call `_repo.nu` makes
# for repo-root. Both config forms, with upstream's own rule for each: a path,
# resolved above; and the inline `key::` form, which already is that material.
#
# Never a fallback, in either direction. A missing key file raises instead of
# deferring to the trust list, because `seal` fails on that same config and a
# record authored under a key this device cannot sign the root with is a record
# that can never bind. And an absent config raises instead of taking the single
# registered key as the answer: that key is not necessarily YOURS — the trust
# list is where a foreign key belongs (upstream invites `alice.pub` into it),
# so counting one file would author under whoever happens to be listed, with no
# error until `verify` reports the binding false.
def signing-pubkey [root: path key: any]: nothing -> string {
    # An explicit key answers before git config is read: `bundle --key` names
    # the identity outright, and must not depend on a config it bypassed.
    if $key != null { return (key-pubkey $key) }
    let git = do { ^git -C $root config user.signingKey } | complete

    if $git.exit_code != 0 or ($git.stdout | str trim | is-empty) {
        error make {msg: "no git `user.signingKey` in this checkout, so nothing says which registered key writes here — set it with: git config user.signingKey <path-to-key>"}
    }
    let raw = $git.stdout | str trim

    if ($raw | str starts-with "key::") {
        return ($raw | str replace "key::" "" | pubkey canonical)
    }
    key-pubkey $raw
}

# --key: sign as this key instead of the checkout's configured one. Only
# `bundle` passes it, because only `bundle` has an operator-facing --key of its
# own; a write command resolves its identity from the config `seal` will use.
export def own-signer [root: path --key: path]: nothing -> string {
    let pubs = list-files ($root | path join multiproofs pubkeys) --suffix ".pub"

    if ($pubs | is-empty) {
        error make {msg: "no pubkey registered in multiproofs/pubkeys/ — run `nu-cybergraph init` first"}
    }
    let mine = signing-pubkey $root $key
    let registered = $pubs | where (open --raw $it) == $mine

    # Registration is what makes a signature readable: a record naming a signer
    # the trust list holds no key for fails the binding at `verify`, `bundle`
    # and `import`. Refuse before writing it, not three commands later.
    if ($registered | is-empty) {
        let which = if $key == null { "the key this checkout signs with" } else { $"the key ($key)" }
        error make {msg: $"($which) is not registered in multiproofs/pubkeys/ — register it with `nu-cybergraph init --pubkey <path-to-key>.pub`"}
    }
    open --raw ($registered | first) | into binary | cid-v0
}

# The signer a write command authors under: `--signer` names a key,
# `--keyless-signer` a name with no key behind it, and neither means this
# repo's own identity.
#
# `--signer` is a CID v0, taken as given, or a key file on this machine, which
# must be registered — the same match `own-signer` makes for user.signingKey.
# Any other string is refused rather than published: the flag reads as "which
# key", and a string published as its own bytes names a signer no key can bind,
# so `verify` reports it NOT BOUND long after the link was written.
#
# `--keyless-signer` is that keyless name on purpose — several identities in
# one repo, which `init` cannot give, since it registers exactly one key. It is
# published under particles/ as its own bytes, whatever its shape, so a name
# with a dot or a slash (`agent-1.v2`) is never read as a path. Checked first,
# before anything is published: `--keyless-signer` writes a particle, and a
# refused pair must leave none behind.
#
# A CID is never checked against particles/. A signer identity is the CID of a
# pubkey FILE, and those live in multiproofs/pubkeys/ — `own-signer`'s own
# answer would fail that check.
export def resolve-signer [root: path signer: any keyless_signer: any]: nothing -> string {
    if $signer != null and $keyless_signer != null {
        error make {msg: "--signer and --keyless-signer are alternatives: --signer names a key, --keyless-signer a name with no key behind it"}
    }
    if $keyless_signer != null { return ($keyless_signer | into binary | particle-store $root) }
    if $signer == null { return (own-signer $root) }
    if $signer =~ $CID_V0_RE { return $signer }
    if not ($signer | path expand | path exists) {
        error make {msg: $"--signer ($signer) is neither a CID v0 nor a key file on this machine — for a name with no key behind it, use --keyless-signer ($signer)"}
    }
    own-signer $root --key $signer
}

# The signer of a cyberlink a record points at — someone else's, as often as
# not. A CID v0 is taken as given; a key file on this machine is that key's
# identity, the CID of its canonical public line; any other string is a keyless
# name and is published as its own bytes, as `--keyless-signer` publishes it. No
# registration check: confirming another signer's link must not need their key
# in this trust list.
export def reference-signer [root: path signer: string]: nothing -> string {
    if $signer =~ $CID_V0_RE { return $signer }
    if ($signer | path expand | path exists) { return (key-pubkey $signer | into binary | cid-v0) }
    $signer | into binary | particle-store $root
}
