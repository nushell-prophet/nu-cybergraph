# Seal the signer's repo and freeze birth certificates for newborn links.
#
# A birth certificate is the inclusion proof extracted from the FIRST seal
# that catalogued the link, frozen in certs/ and never regenerated. Its OTS
# anchor is the link's earliest provable time bound; later seals only add
# newer roots and must not touch existing certificates.

use _repo.nu graph-root
use _fs.nu [list-files copy-file move-file]
use _layout.nu [links-dir certs-dir cert-path snapshot-dir receipts-dir receipt-cert-path receipt-relpath LINKS_DIR CERTS_DIR SEALS_DIR IMPORTED_DIR RECEIPTS_DIR]
use _record.nu [read-link]
use _deps/seal.nu [seal]
use _deps/merkle.nu [merkle]

# Whatever stands where a frozen proof belongs must be that proof. Absent is the
# normal answer for a link that has not been sealed yet, and it is the only other
# one allowed.
#
# Three shapes, all measured to pass the bare-existence reading this replaces: a
# directory, an empty file, and a genuine proof belonging to a DIFFERENT link.
# The last is why the check reads `leaf.filepath` instead of stopping at "parses
# as JSON" — a proof copied or renamed to the wrong name certifies the wrong
# record, and that is what a hand-repaired graph produces.
#
# No try/catch around `open`. A file that is not JSON raises upstream's own error
# naming the file, and rebuilding it from `$e.msg` would drop the parse position,
# help, labels and span — `$e.msg` alone is the four words "Error while parsing
# as json" (measured). That rebuild is the defect 62c1c5b removed from verify.nu;
# it is not reintroduced here.
#
# The optional cell path is what makes that possible: an EMPTY .json file does
# not raise in `open`, it returns nothing (measured), and `get leaf?.filepath?`
# turns both that and a well-formed file of the wrong shape into null — which is
# a verdict this function can phrase, naming the link that went uncertified.
def assert-frozen-proof [proof: path leaf: string]: nothing -> nothing {
    if ($proof | path type) == null { return }
    if ($proof | path type) != "file" {
        error make {msg: $"($proof) is a ($proof | path type), not the frozen proof for ($leaf) — remove it and seal again"}
    }
    let named = open $proof | get leaf?.filepath?
    if $named == null {
        error make {msg: $"($proof) carries no leaf.filepath, so it is not a frozen proof for ($leaf) — remove it and seal again"}
    }
    if $named != $leaf {
        error make {msg: $"($proof) is the frozen proof for ($named), not for ($leaf) — a proof under the wrong name certifies the wrong record; remove it and seal again"}
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
    --response-file: path # TESTS ONLY: take the calendar's answer from this file instead of posting the digest
]: nothing -> record {
    let root = graph-root $repo

    # Refused rather than given a precedence, and before anything is staged: with
    # --no-stamp the whole stamping step is skipped, so the calendar answer is
    # read by nobody and a test written that way LOOKS like it stamped while
    # asserting nothing. Upstream refuses its own contradictory pair with the
    # same argument (nu-multiproof/seal.nu, --no-stamp vs --no-content-anchor).
    if $no_stamp and $response_file != null {
        error make {msg: "--no-stamp and --response-file are alternatives: --no-stamp skips stamping entirely, so the calendar answer would be read by no one"}
    }

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
    #
    # The second check in the same pass answers a different question about the
    # same link: the freeze loops below decide "this one already has a
    # certificate" from its cert path alone, and every reader downstream trusts
    # that answer, so whatever stands there has to BE the frozen proof for this
    # link. Cost measured at 7.3 ms of parsing over 199 certificates against a
    # 4 s seal.
    #
    # Why here rather than inside the filter: a seal that discovers the problem
    # later has already git-added certs/, so an operator who then deletes the bad
    # node walks into upstream's `tracked paths do not resolve to regular files`,
    # naming a file they just removed, and only `git rm -r --cached` clears it
    # (measured). Refused before staging, removing the node is the whole recovery.
    for f in (list-files (links-dir $root) --suffix ".json") {
        read-link $f
        assert-frozen-proof (cert-path $root (($f | path parse).stem)) ($f | path relative-to $root)
    }

    # Receipts, same rule. The leaf comes from `receipt-relpath`, which _layout.nu
    # documents as being exactly this proof's `leaf.filepath` — the alternative,
    # re-deriving it with `path relative-to`, would be a third spelling of a path
    # the layout module already owns.
    for f in (list-files (receipts-dir $root) --suffix ".receipt.json") {
        let cid = $f | path basename | str replace ".receipt.json" ""
        assert-frozen-proof (receipt-cert-path $root $cid) (receipt-relpath $cid)
    }

    # Stage the cybergraph dirs: the manifest walks `git ls-files`, so an
    # untracked newborn link would silently miss its own seal. certs/ and
    # seals/ hold artifacts of PREVIOUS seals — cataloguing them makes each
    # seal also attest the certificates issued so far (custody continuity).
    # imported/ is the custody layer itself: cataloguing a foreign bundle is
    # what proves "this signer held the link no later than block K"; receipts/
    # is that claim made portable — the statement `bundle` re-exports.
    #
    # This list only ADDS; it is not the manifest's scope. The manifest is every
    # git-tracked file under the graph home EXCEPT `multiproofs/`, which upstream
    # drops as derived output (`_tracked.nu`: hashing it would make the manifest
    # mutate every seal on a new .ots nonce, and a manifest cannot hash itself).
    # Two consequences worth naming, both measured: a file this list never
    # mentions is sealed anyway once the operator commits it (a `scratch/junk.txt`
    # appears in the manifest after a plain `git add -A`), and the registered
    # pubkey is NOT under the seal — it is git-tracked and has zero manifest rows,
    # because it lives in `multiproofs/pubkeys/`.
    #
    # A REPEATED SEAL IS NOT A NO-OP, and that follows from `seals/` being here.
    # Each seal ends by writing `seals/<root12>/`, holding that seal's root
    # statement and its signature; the next seal catalogues that directory, so
    # its manifest differs, so its root differs, so it writes another directory.
    # A fixpoint would need a directory named after a root computed from a tree
    # that already contains it — a hash self-reference, so not reachable.
    #
    # Measured over five consecutive seals with nothing added between them: five
    # distinct roots, `seals/` grown 1 -> 5 directories, manifest rows 3, 9, 12,
    # 15, 18. The +6 at seal 2 is `certs/`, the first certificate and the `seals`
    # parent row all entering at once; +3 per seal after that, being one snapshot
    # directory and its two files. What it buys is the continuity above — each
    # seal re-attests the root statements and signatures of every seal before it.
    # What it costs, with stamping on, is a fresh signature and a calendar round
    # trip per empty run, while README advises sealing on every append.
    #
    # Accepted with that cost, not designed this way. Dropping `seals/` from this
    # list DOES converge — measured, a fixpoint at the second seal — but only
    # while the graph stays untracked by git: once it is committed, the directory
    # re-enters the manifest through `git ls-files` and the growth returns. So it
    # is a fix conditional on a state a shared graph has to leave, which is why
    # it was not taken. The lever that would work unconditionally, gitignoring
    # `seals/`, means the snapshots are never committed, so every clone loses
    # them — and with them the ability to verify or export any link born under
    # those roots. Pinned by tests/test_bootstrap.nu "a seal with nothing new
    # still mints a new root".
    let stage = [$LINKS_DIR $CERTS_DIR $SEALS_DIR $IMPORTED_DIR $RECEIPTS_DIR]
        | each {|d| $root | path join $d }
        | where (($it | path exists) and (ls $it | is-not-empty))
    if ($stage | is-not-empty) {
        ^git -C $root add -- ...$stage
    }

    # --no-content-anchor is passed unconditionally, and this repo exposes no flag
    # of its own for it: one form is the whole point. A bundle holding an anchor
    # over tree-root.txt AND one over the signature over it does not say which
    # dates the statement — both are true, neither is derived from the other on
    # disk — so each reader answers for itself which is the time, what a
    # disagreement means, and whether verification needs one or both. An option
    # here would put those three questions back.
    #
    # A link is an assertion by a signer, so the endorsement anchor IS the claim;
    # an anchor over the root alone dates bytes without saying who asserted them.
    # Upstream keeps both by default on purpose (nu-multiproof de3c2dd) — an
    # archive that must stay checkable with no key material wants the content
    # anchor, because deriving content-time through the signature inherits every
    # way SSH verification can rot. That trade is taken here knowingly.
    #
    # Tied to $no_stamp rather than passed bare: upstream refuses the two flags
    # together, because --no-stamp skips step 4 entirely while --no-content-anchor
    # runs it over the signatures only. So the rule reads "whenever this repo
    # stamps at all, it stamps signatures only" — which is the invariant, not a
    # flag combination.
    #
    # --response-file is forwarded, not re-implemented: it is upstream's own test
    # seam, and without it nothing here could reach a real stamp offline — every
    # test seals --no-stamp, so every anchor read `absent`. It must never appear
    # in a real seal: the anchor would attest a fixture, not a calendar's answer.
    let sealed = seal --repo $root --no-stamp=$no_stamp --no-content-anchor=(not $no_stamp) --response-file $response_file
    let root_hex = $sealed.merkle_root

    # Snapshot this seal's root statement + signatures. multiproofs/tree-root.txt
    # is overwritten by every seal, but certificates verify against the root
    # they were born under — the snapshot is what `bundle` exports later.
    #
    # BEFORE the freeze loops, not after: the snapshot depends only on the seal
    # that has just happened, and the loops below can fail part-way — `merkle
    # prove` throws for a link the filesystem lists but git does not track. With
    # the snapshot written last, such a failure left certificates frozen naming a
    # root NO snapshot existed for, while tree-root.txt and its signature had
    # already been overwritten — `bundle` and `verify` for those links then
    # failed forever, and re-sealing could not repair it because the retry mints
    # a different root. Written first, the same failure is recoverable: the root
    # the frozen certificates name still has its snapshot on disk. Pinned by
    # tests/test_bootstrap.nu "a freeze loop that fails still leaves the snapshot
    # its certificates name" — the success path is identical either way, so only
    # a failed loop can tell the two orderings apart.
    let snap = snapshot-dir $root $root_hex
    # Why the guard never fires in this module's own flow, and why that is not an
    # accident to rely on quietly: `snapshot-dir` is keyed by the merkle root, and
    # every seal mints a new root — because `$stage` above includes `seals/`. The
    # dependency is 50 lines away and nothing here would show it.
    #
    # Take `seals/` out of `$stage` for any reason and two seals can share a
    # root, at which point this guard starts firing: the snapshot keeps the FIRST
    # seal's signature while `multiproofs/` holds the second. Both are valid over
    # the same bytes, so nothing breaks today — but the guard would then be live
    # code that has never run, and it tests the DIRECTORY, so a snapshot
    # interrupted between `mkdir` and the copies stays empty forever if that root
    # ever recurs. Testing `tree-root.txt` instead is the fix that belongs with
    # that change, not before it.
    if not ($snap | path exists) {
        mkdir $snap
        copy-file ($root | path join multiproofs tree-root.txt) $snap
        # Both sig spellings nu-multiproof's _sig.nu knows: the named
        # `<file>.<fingerprint>.sig` and the bare `<file>.sig`.
        #
        # `for`, not `each`: a raise inside an `each` closure comes back as
        # "Eval block failed with pipeline input" and copy-file's message would
        # never reach the operator. The snapshot is written once and never
        # rebuilt (the guard above), so a half-copied one would stay half-copied
        # for as long as that root is referenced — which is why the operator has
        # to be able to read what went wrong. Since this block moved ahead of the
        # freeze loops it is no longer a dead end: a raise here happens before any
        # certificate is frozen, so no certificate names this root and the retry
        # simply mints a new one.
        for s in (
            list-files ($root | path join multiproofs) --suffix ".sig"
            | where ($it | path basename | str starts-with "tree-root.txt.")
        ) {
            copy-file $s $snap
        }
    }

    # Freeze birth certificates for links that don't have one yet.
    #
    # "Has one" is bare existence, and that is only safe because the sweep above
    # has already refused every node here that is not a frozen proof for this
    # exact link. Without it, `path exists` answered true for a DIRECTORY or an
    # EMPTY FILE at the cert path — measured, both: seal reported success with
    # newborn=0 while the link went uncertified but WAS catalogued under that
    # root, so the certificate a later seal wrote named a later root than the
    # link's birth. The birth invariant broken with no error anywhere.
    #
    # Deliberately not re-checked here: within `seal` the rule has one place. If
    # the sweep is ever removed, this line silently becomes wrong again.
    #
    # The claim stops at seal's edge. `verify.nu` and `bundle.nu` still answer
    # "is there a certificate" with a bare `path exists` and the sweep never runs
    # for them, so a junk node at a cert path still reaches those two as a crash
    # rather than a verdict — parked, not fixed here.
    mkdir (certs-dir $root)
    let newborn = list-files (links-dir $root) --suffix ".json"
        | where (not ((cert-path $root (($it | path parse).stem)) | path exists))
    for f in $newborn {
        let proof = merkle prove ($f | path relative-to $root) --repo $root
        move-file $proof (cert-path $root (($f | path parse).stem))
    }

    # Same freeze rule for custody receipts, resting on the same sweep: the FIRST
    # seal that catalogues a receipt sets its earliest provable custody bound, so
    # its proof freezes beside it and later seals must not touch it.
    # (*.receipt.cert.json does not end with .receipt.json — the suffix skips
    # already-frozen proofs.)
    let new_receipts = list-files (receipts-dir $root) --suffix ".receipt.json"
        | where (not ((receipt-cert-path $root ($it | path basename | str replace ".receipt.json" "")) | path exists))
    for f in $new_receipts {
        let proof = merkle prove ($f | path relative-to $root) --repo $root
        move-file $proof (receipt-cert-path $root ($f | path basename | str replace ".receipt.json" ""))
    }

    {sealed: $sealed newborn: ($newborn | length) receipts: ($new_receipts | length) snapshot: $snap}
}
