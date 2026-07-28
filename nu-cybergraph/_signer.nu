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
use _deps/cid-v0.nu [cid-v0]

export def own-signer [root: path]: nothing -> string {
    let pubs = list-files ($root | path join multiproofs pubkeys) --suffix ".pub"
    match ($pubs | length) {
        0 => (error make {msg: "no pubkey registered in multiproofs/pubkeys/ — run `nu-cybergraph init` first"})
        1 => (open --raw ($pubs | first) | into binary | cid-v0)
        _ => (error make {msg: "multiple pubkeys registered — this repo has no single signer identity; pass --signer where the command takes one"})
    }
}
