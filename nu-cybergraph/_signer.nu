# This repo's own signer identity — the CID of its single registered pubkey.
#
# One definition, because it is one question: "who is this repo?". It used to
# be answered twice (link.nu's own-signer-cid for the record's `signer` field,
# _receipt.nu's own-signer for the custodian) with two counts of pubkeys and
# two sets of error messages — a fork waiting to drift, in the one place where
# a wrong answer signs a statement under the wrong name.
#
# `init` canonicalizes the key at registration, so the file bytes ARE the
# canonical form — hash them directly. Several registered keys is an error,
# never a pick: one keypair is one signer, and choosing for the operator would
# author under a key they did not name.

use _fs.nu list-files
use _particle.nu [ particle-store ]
use _validate.nu [ CID_V0_RE ]
use _deps/cid-v0.nu [ cid-v0 ]

export def own-signer [root: path]: nothing -> string {
    let pubs = list-files ($root | path join multiproofs pubkeys) --suffix ".pub"
    match ($pubs | length) {
        0 => (error make {msg: "no pubkey registered in multiproofs/pubkeys/ — run `nu-cybergraph init` first"})
        1 => (open --raw ($pubs | first) | into binary | cid-v0)
        # Names the condition, not a remedy: two of the three callers (import,
        # bundle) have no --signer flag to offer, and pointing an operator at a
        # flag that does not exist is worse than the old message this replaced.
        _ => (error make {msg: $"multiple pubkeys registered in multiproofs/pubkeys/ \(($pubs | length)) — this repo has no single signer identity"})
    }
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
