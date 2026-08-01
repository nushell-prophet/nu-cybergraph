# Seal the signer's repo and freeze birth certificates for newborn links.
#
# A birth certificate is the inclusion proof extracted from the FIRST seal
# that catalogued the link, frozen in certs/ and never regenerated. Its OTS
# anchor is the link's earliest provable time bound; later seals only add
# newer roots and must not touch existing certificates.

use _repo.nu graph-root
use _fs.nu list-files
use _layout.nu [links-dir certs-dir cert-path snapshot-dir receipts-dir receipt-cert-path LINKS_DIR CERTS_DIR SEALS_DIR IMPORTED_DIR RECEIPTS_DIR]
use _record.nu [read-link]
use _deps/seal.nu [seal]
use _deps/merkle.nu [merkle]

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

    # Upstream's seal now asks its registration question before rewriting
    # anything (nu-multiproof 923daa1), so the fingerprint pre-check that
    # lived here — with its own copy of the signing-key resolution — is gone
    # with it. What stays is the bootstrap case upstream cannot name: an empty
    # pubkeys/ means `nu-cybergraph init` has not run, and registration is
    # deliberate — it establishes the signer identity — so seal points there
    # instead of registering as a side effect.
    let registered = list-files ($root | path join multiproofs pubkeys) --suffix ".pub"
    if ($registered | is-empty) {
        error make {msg: "no pubkey registered in multiproofs/pubkeys/ — run `nu-cybergraph init` first"}
    }

    # Self-addressing is the format's contract for every reader, but until now
    # only verify/import enforced it. `seal` is where a file crosses from junk
    # on disk to a statement signed by this signer: a tampered or hand-written
    # non-canonical record would get catalogued, signed, and frozen into a
    # birth certificate that proves the signer attested a file which is not its
    # own address. Check here, at that boundary, and before multiproof's seal
    # mutates anything.
    #
    # Every link, not just the newborns: each seal re-attests the whole
    # catalogue, so a record tampered with after its birth seal must abort this
    # one too. Cost is one sha256 per link per seal, against a seal that
    # already signs and stamps.
    for f in (list-files (links-dir $root) --suffix ".json") {
        read-link $f
    }

    # Stage the cybergraph dirs: the manifest walks `git ls-files`, so an
    # untracked newborn link would silently miss its own seal. certs/ and
    # seals/ hold artifacts of PREVIOUS seals — cataloguing them makes each
    # seal also attest the certificates issued so far (custody continuity).
    # imported/ is the custody layer itself: cataloguing a foreign bundle is
    # what proves "this signer held the link no later than block K"; receipts/
    # is that claim made portable — the statement `bundle` re-exports.
    let stage = [$LINKS_DIR $CERTS_DIR $SEALS_DIR $IMPORTED_DIR $RECEIPTS_DIR]
        | each {|d| $root | path join $d }
        | where (($it | path exists) and (ls $it | is-not-empty))
    if ($stage | is-not-empty) {
        ^git -C $root add -- ...$stage
    }

    let sealed = seal --repo $root --no-stamp=$no_stamp
    let root_hex = $sealed.merkle_root

    # Freeze birth certificates for links that don't have one yet.
    mkdir (certs-dir $root)
    let newborn = list-files (links-dir $root) --suffix ".json"
        | where (not ((cert-path $root (($it | path parse).stem)) | path exists))
    for f in $newborn {
        let proof = merkle prove ($f | path relative-to $root) --repo $root
        mv $proof (cert-path $root (($f | path parse).stem))
    }

    # Same freeze rule for custody receipts: the FIRST seal that catalogues a
    # receipt sets its earliest provable custody bound, so its proof freezes
    # beside it and later seals must not touch it. (*.receipt.cert.json does
    # not end with .receipt.json — the suffix skips already-frozen proofs.)
    let new_receipts = list-files (receipts-dir $root) --suffix ".receipt.json"
        | where (not ((receipt-cert-path $root ($it | path basename | str replace ".receipt.json" "")) | path exists))
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
        # Both sig spellings nu-multiproof's _sig.nu knows: the named
        # `<file>.<fingerprint>.sig` and the bare `<file>.sig`.
        list-files ($root | path join multiproofs) --suffix ".sig"
        | where ($it | path basename | str starts-with "tree-root.txt.")
        | each {|s| cp $s $snap }
    }

    {sealed: $sealed newborn: ($newborn | length) receipts: ($new_receipts | length) snapshot: $snap}
}
