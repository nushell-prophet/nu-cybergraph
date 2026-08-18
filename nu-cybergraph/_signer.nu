# This repo's own signer identity — the CID of the registered pubkey this
# checkout writes under.
#
# One definition, because it is one question: "who is this repo?". It used to
# be answered twice (link.nu's own-signer-cid for the record's `signer` field,
# _receipt.nu's own-signer for the custodian) with two counts of pubkeys and
# two sets of error messages — a fork waiting to drift, in the one place where
# a wrong answer signs a statement under the wrong name.
#
# It also used to be answered by COUNTING those pubkeys: exactly one was the
# identity, and several were an error. That derived the answer from the wrong
# directory. `multiproofs/pubkeys/` is nu-multiproof's TRUST LIST — the keys
# whose signatures this repo accepts — and a second key belongs there on
# purpose: a co-signer adds its signature to a frozen seal snapshot, which is
# how one operator holding keys on several devices makes a statement expensive
# to forge (measured: two signatures under one root, `verify` still bound).
# Counting answered "who am I" with "whom do I trust", so a graph that gained a
# co-signer could no longer write a link at all.
#
# The identity is this checkout's own signing key instead — the same
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
        error make {msg: $"signing key not on this machine: ($named)"}
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
    let registered = $pubs | where {|f| (open --raw $f) == $mine }
    # Registration is what makes a signature readable: a record naming a signer
    # the trust list holds no key for fails the binding at `verify`, `bundle`
    # and `import`. Refuse before writing it, not three commands later.
    if ($registered | is-empty) {
        error make {msg: "the key this checkout signs with is not registered in multiproofs/pubkeys/ — register it with `nu-cybergraph init --pubkey <path-to-key>.pub`"}
    }
    open --raw ($registered | first) | into binary | cid-v0
}

# What a write command's `--signer` resolves to. Null falls back to this repo's
# own identity above; a CID v0 is taken as given; any other string is published
# under particles/ as its own bytes, and its CID is the signer. Ad-hoc names
# are what that is for — several identities in one repo, which `init` cannot
# give, since it registers exactly one key.
#
# Two rules an endpoint has that the signer deliberately does not:
#
# A string is NEVER opened as a path. `--signer other.pub` publishes the eight
# characters, not the key file. An endpoint reads a path because a bare
# argument there all but always means "publish this file"; a signer names an
# identity, so a path branch bought nothing and cost the plain case — a name
# carrying a dot or a slash (`agent-1.v2`) would be refused as a probable typo,
# and the escape hatch was a flag shared with the endpoints. Publishing a key
# file composes instead: `particle add other.pub`, then pass the CID.
#
# A CID is never checked against particles/. A signer identity is the CID of a
# pubkey FILE, and those live in multiproofs/pubkeys/ — `own-signer`'s own
# answer would fail that check.
export def resolve-signer [root: path signer: any]: nothing -> string {
    if $signer == null { return (own-signer $root) }
    if $signer =~ $CID_V0_RE { return $signer }
    $signer | into binary | particle-store $root
}
