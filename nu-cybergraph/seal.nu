# Seal the neuron repo and freeze birth certificates for newborn links.
#
# A birth certificate is the inclusion proof extracted from the FIRST seal
# that catalogued the link, frozen in certs/ and never regenerated. Its OTS
# anchor is the link's earliest provable time bound; later seals only add
# newer roots and must not touch existing certificates.

use _repo.nu graph-root
use _layout.nu [links-dir certs-dir cert-path snapshot-dir receipts-dir receipt-cert-path LINKS_DIR CERTS_DIR SEALS_DIR IMPORTED_DIR RECEIPTS_DIR]
use _record.nu [read-link]
use _deps/seal.nu [seal]
use _deps/merkle.nu [merkle]
use _deps/pubkey.nu [pubkey]

# The public half of the key this repo's git config will sign with, plus how to
# name it back to the operator. Both forms git allows: inline `key::<line>`
# material, or a path whose `.pub` sibling holds the public half.
#
# Why resolved here rather than imported from nu-multiproof's _key-helpers.nu:
# cross-repo imports of another project's `_`-internals carry no compatibility
# promise — the same call _repo.nu made for repo-root.
def signing-pubkey [root: path]: nothing -> record<line: string, desc: string, hint: string> {
    let cfg = ^git -C $root config user.signingKey | complete
    if $cfg.exit_code != 0 or ($cfg.stdout | str trim | is-empty) {
        error make {msg: "no signing key configured — set git config user.signingKey in the repo seal targets"}
    }
    let raw = $cfg.stdout | str trim
    if ($raw | str starts-with "key::") {
        {line: ($raw | str replace "key::" "") desc: "the inline user.signingKey" hint: ""}
    } else {
        let expanded = $raw | path expand
        let pub = if ($expanded | str ends-with ".pub") { $expanded } else { $"($expanded).pub" }
        if not ($pub | path exists) {
            error make {msg: $"the signing key's public half is not on disk: ($pub)"}
        }
        {line: (open --raw $pub) desc: $pub hint: $" --pubkey ($pub)"}
    }
}

# `seal` in the body is nu-multiproof's seal; this wrapper stages the
# cybergraph files, runs it, then freezes certificates and the root snapshot.
#
# No --key: the signing identity is the repo's, read from its git config, which
# is where multiproof's seal reads it too.
export def main [
    --repo: path # Target git repo root (default: git root of current directory)
    --no-stamp # Skip OTS timestamping (stamping is the point — tests only)
]: nothing -> record {
    let root = graph-root $repo

    # Fail fast BEFORE multiproof's seal mutates anything: it rewrites the
    # manifest and the root statement — and deletes signatures over bytes that
    # changed — in its step 2, while its own registration check (`ssh-sign
    # sign` → signing-principal) only fires in step 3, once that is done. Same
    # invariant, asked before the damage instead of after; that ordering is the
    # only reason this is not a duplicate of upstream's check. Registration is
    # deliberate — it establishes the neuron identity — so seal points to init
    # instead of registering as a side effect.
    let registered = glob ($root | path join multiproofs pubkeys *.pub)
    if ($registered | is-empty) {
        error make {msg: "no pubkey registered in multiproofs/pubkeys/ — run `nu-cybergraph init` first"}
    }
    # Compare fingerprints, not `<type> <base64>` text: upstream a principal IS
    # the key's own fingerprint, and `pubkey fingerprint` canonicalizes on the
    # way in — so this asks the same question multiproof will ask, in the same
    # terms, instead of a hand-rolled string compare that reads a padded copy of
    # a registered key as a different key.
    let signing = signing-pubkey $root
    let known = $registered | each {|f| open --raw $f | pubkey fingerprint }
    if ($signing.line | pubkey fingerprint) not-in $known {
        error make {msg: $"($signing.desc) is not registered in multiproofs/pubkeys/ — run `nu-cybergraph init($signing.hint)` first"}
    }

    # Self-addressing is the format's contract for every reader, but until now
    # only verify/import enforced it. `seal` is where a file crosses from junk
    # on disk to a statement signed by this neuron: a tampered or hand-written
    # non-canonical record would get catalogued, signed, and frozen into a
    # birth certificate that proves the neuron attested a file which is not its
    # own address. Check here, at that boundary, and before multiproof's seal
    # mutates anything — same reason as the pubkey block above.
    #
    # Every link, not just the newborns: each seal re-attests the whole
    # catalogue, so a record tampered with after its birth seal must abort this
    # one too. Cost is one sha256 per link per seal, against a seal that
    # already signs and stamps.
    for f in (glob (links-dir $root | path join *.json)) {
        read-link $f
    }

    # Stage the cybergraph dirs: the manifest walks `git ls-files`, so an
    # untracked newborn link would silently miss its own seal. certs/ and
    # seals/ hold artifacts of PREVIOUS seals — cataloguing them makes each
    # seal also attest the certificates issued so far (custody continuity).
    # imported/ is the custody layer itself: cataloguing a foreign bundle is
    # what proves "this neuron held the link no later than block K"; receipts/
    # is that claim made portable — the statement `bundle` re-exports.
    let stage = [$LINKS_DIR $CERTS_DIR $SEALS_DIR $IMPORTED_DIR $RECEIPTS_DIR]
        | each {|d| $root | path join $d }
        | where {|d| ($d | path exists) and (ls $d | is-not-empty) }
    if ($stage | is-not-empty) {
        ^git -C $root add -- ...$stage
    }

    let sealed = seal --repo $root --no-stamp=$no_stamp
    let root_hex = $sealed.merkle_root

    # Freeze birth certificates for links that don't have one yet.
    mkdir (certs-dir $root)
    let newborn = glob (links-dir $root | path join *.json)
        | where {|f| not ((cert-path $root (($f | path parse).stem)) | path exists) }
    for f in $newborn {
        let proof = merkle prove ($f | path relative-to $root) --repo $root
        mv $proof (cert-path $root (($f | path parse).stem))
    }

    # Same freeze rule for custody receipts: the FIRST seal that catalogues a
    # receipt sets its earliest provable custody bound, so its proof freezes
    # beside it and later seals must not touch it. (*.receipt.cert.json does
    # not match *.receipt.json — the glob skips already-frozen proofs.)
    let new_receipts = glob (receipts-dir $root | path join *.receipt.json)
        | where {|f| not ((receipt-cert-path $root ($f | path basename | str replace ".receipt.json" "")) | path exists) }
    for f in $new_receipts {
        let proof = merkle prove ($f | path relative-to $root) --repo $root
        mv $proof (receipt-cert-path $root ($f | path basename | str replace ".receipt.json" ""))
    }

    # Snapshot this seal's root statement + signatures. multiproofs/tree-root.txt
    # is overwritten by every seal, but certificates verify against the root
    # they were born under — the snapshot is what `bundle` exports later.
    let snap = snapshot-dir $root $root_hex
    if not ($snap | path exists) {
        mkdir $snap
        cp ($root | path join multiproofs tree-root.txt) $snap
        glob ($root | path join multiproofs tree-root.txt.*sig) | each {|s| cp $s $snap }
    }

    {sealed: $sealed newborn: ($newborn | length) receipts: ($new_receipts | length) snapshot: $snap}
}
