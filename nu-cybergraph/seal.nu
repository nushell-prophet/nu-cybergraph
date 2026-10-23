# Seal the signer's repo and freeze birth certificates for newborn links.
#
# A birth certificate is the inclusion proof extracted from the FIRST seal
# that catalogued the link, frozen in certs/ and never regenerated. Its OTS
# anchor is the link's earliest provable time bound; later seals only add
# newer roots and must not touch existing certificates.

use _repo.nu graph-root
use _fs.nu [ list-files copy-file move-file cwd-relative ]
use _layout.nu [ signer-dirs link-files certs-dir cert-path snapshot-dir seals-dir receipts-dir receipt-files receipt-cert-path receipt-relpath order-files order-cert-path order-relpath strays CERTS_DIR SEALS_DIR IMPORTED_DIR RECEIPTS_DIR ORDER_DIR ]
use _record.nu [ read-link ]
use _validate.nu [ CID_V0_RE ]
use _signer.nu [ own-signer ]
use _commit-proposal.nu [ seal-commit-line ]
use _uncommitted.nu [ uncommitted-files stageable ]
use _order.nu [ assert-bijection assert-numbered-run number-provisional ]
use _deps/seal.nu [ seal ]
use _deps/merkle.nu [ merkle ]

# Whatever stands where a frozen proof belongs must be that proof. Absent is the
# normal answer for a link that has not been sealed yet, and it is the only other
# one allowed.
#
# Three shapes pass a bare-existence reading, all measured: a directory, an
# empty file, and a genuine proof belonging to a DIFFERENT link.
# The last is why the check reads `leaf.filepath` instead of stopping at "parses
# as JSON" — a proof copied or renamed to the wrong name certifies the wrong
# record, and that is what a hand-repaired graph produces.
#
# No try/catch around `open`. A file that is not JSON raises upstream's own error
# naming the file, and rebuilding it from `$e.msg` would drop the parse position,
# help, labels and span — `$e.msg` alone is the four words "Error while parsing
# as json" (measured).
#
# The optional cell path is what makes that possible: an EMPTY .json file does
# not raise in `open`, it returns nothing (measured), and `get --optional`
# turns both that and a well-formed file of the wrong shape into null — which is
# a verdict this function can phrase, naming the link that went uncertified.
export def assert-frozen-proof [proof: path leaf: string]: nothing -> nothing {
    if ($proof | path type) == null { return }
    if ($proof | path type) != "file" {
        error make {msg: $"($proof) is a ($proof | path type), not the frozen proof for ($leaf)" help: "remove it and seal again"}
    }
    let named = open $proof | get --optional leaf.filepath

    if $named == null {
        error make {msg: $"($proof) carries no leaf.filepath, so it is not a frozen proof for ($leaf)" help: "remove it and seal again"}
    }
    if $named != $leaf {
        error make {msg: $"($proof) is the frozen proof for ($named), not for ($leaf) — a proof under the wrong name certifies the wrong record" help: "remove it and seal again"}
    }
}

# `seal` in the body is nu-multiproof's seal; this wrapper stages the
# cybergraph files, runs it, then freezes certificates and the root snapshot.
#
# No --key: the signing identity is the repo's, read from its git config, which
# is where multiproof's seal reads it too.
#
# Committing is deliberately outside this pipeline, as it is upstream: it is the
# operator's decision, with context the seal does not have. `--propose-commit`
# does not weaken that — it writes the command into the prompt to be read, edited
# and run — it only fixes the wording, so a seal does not land under "wip" or
# split over three commits.
@category cybergraph
export def main [
    --repo: path # Target repo root (default: the nearest dir holding cybergraph/, up to the git root)
    --no-stamp # Skip OTS timestamping (stamping is the point — tests only)
    --response-file: path # TESTS ONLY: take the calendar's answer from this file instead of posting the digest
    --propose-commit # Leave a `git commit` for this seal in the prompt, unrun
    --allow-untracked-particles # Seal without the store files the graph names (see the guard below)
    --external-signer # The root is signed on another device: run, sign there, run again (upstream's flag)
]: nothing -> record {
    let root = graph-root $repo

    # Refused rather than given a precedence, and before anything is staged: with
    # --no-stamp the whole stamping step is skipped, so the calendar answer is
    # read by nobody and a test written that way LOOKS like it stamped while
    # asserting nothing. Upstream refuses its own contradictory pair with the
    # same argument (nu-multiproof/seal.nu, --no-stamp vs --no-content-anchor).
    if $no_stamp and $response_file != null {
        error make {
            msg: "--no-stamp and --response-file are alternatives: --no-stamp skips stamping entirely, so the calendar answer would be read by no one"
            label: {text: "drop this or --no-stamp" span: (metadata $response_file).span}
        }
    }

    # Upstream's seal asks its registration question before rewriting
    # anything (nu-multiproof's seal.nu). What stays here is the bootstrap
    # case upstream cannot name: an empty pubkeys/ means `nu-cybergraph init`
    # has not run, and registration is deliberate — it establishes the signer
    # identity — so seal points there instead of registering as a side effect.
    let registered = list-files ($root | path join multiproofs pubkeys) --suffix ".pub"

    if ($registered | is-empty) {
        error make {msg: "no pubkey registered in multiproofs/pubkeys/" help: "run `nu-cybergraph init` first"}
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
    for l in (link-files $root) {
        read-link $l.file
        assert-frozen-proof (cert-path $root $l.signer $l.edge) ($l.file | path relative-to $root)
    }

    # Receipts, same rule. The leaf comes from `receipt-relpath`, which _layout.nu
    # documents as being exactly this proof's `leaf.filepath` — the alternative,
    # re-deriving it with `path relative-to`, would be a third spelling of a path
    # the layout module already owns.
    for r in (receipt-files $root) {
        assert-frozen-proof (receipt-cert-path $root $r.author $r.edge) (receipt-relpath $r.author $r.edge)
    }

    # Positions, same rule again, and the same leaf path the layout owns: what
    # stands at a proof path has to BE the proof for that position, or the
    # freeze loop below would leave a signed proof beside bytes it never
    # covered.
    for p in (order-files $root) {
        assert-frozen-proof (order-cert-path $root $p.signer $p.edge) (order-relpath $p.signer $p.edge)
    }

    # The position a link carries in its signer's run is the seal's business
    # twice over. Once as a bijection — every record positioned, every position
    # a record — because a signer who seals a link and does not number it
    # leaves a contiguous run beside an uncounted link, which is the silent
    # thinning the run exists to expose. And once as contiguity of what is
    # already numbered, which cannot be repaired here and so is reported
    # instead (_order.nu says why each is refused where it is).
    assert-bijection $root
    assert-numbered-run $root

    # `$stage` below git-adds the graph home's directories WHOLESALE, so
    # anything sitting in them that the layout does not describe enters this
    # seal's signed manifest unvalidated: attested by the signer while none of
    # the checks that make an attestation mean something — self-addressing,
    # the pre-seal sweep, the certificate freeze — apply to it. Refused before
    # staging, and the recovery is the whole fix: remove the node and seal
    # again.
    #
    # One rule at one point. The tree it enforces is SPEC section 3, which this
    # turns from prose into a check — see `_layout.nu strays`.
    let stray = strays $root

    if ($stray | is-not-empty) {
        let named = $stray | each {|r| $"($r.path | cwd-relative) \(($r.under | path basename) holds ($r.allowed))" } | str join ', '

        error make {msg: $"not the graph layout: ($named) — a seal signs whatever is committed under the graph home, so it refuses while it reaches a file the layout does not describe" help: "remove it and seal again, or move it beside the graph home rather than inside it. `nu-cybergraph strays` lists them without sealing"}
    }

    # Stage the cybergraph dirs — the signer directories holding the link
    # files, plus the fixed set: the manifest walks `git ls-files`, so an
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
    # distinct roots, `seals/` grown 1 -> 5 directories, manifest rows 3, 10, 13,
    # 16, 19. The +7 at seal 2 is `certs/`, the signer's certificate directory
    # under it, the first certificate, the `seals` parent row, and the first
    # snapshot directory with its two files, all entering at once; +3 per seal
    # after that, being one snapshot directory and its two files. What it buys
    # is the continuity above — each seal re-attests the root statements and
    # signatures of every seal before it.
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
    # A store file the graph names but git does not track is bytes no root
    # covers: the manifest walks `git ls-files`, so the link naming it gets
    # signed and frozen while its endpoint is catalogued by nothing.
    #
    # Refused, not staged: publishing the bytes a link names is the operator's
    # act, and `particle uncommitted` is where they read what is about to be
    # committed. So this makes "the seal covers the bytes it names" an invariant
    # instead of a habit, at the price of a command that can now fail on a graph
    # nothing is wrong with.
    #
    # `uncommitted-files` runs whether or not the flag is set, and only the
    # refusal is gated: it also raises on a name under particles/ that is no
    # address at all, which is not something to seal past — a signature over it
    # is the signer attesting what the store's own filename rule rejects. So the
    # flag says "seal without these bytes", never "seal a store whose layout is
    # already broken". A clean store costs one `git status`; the reachability
    # walk runs only when something is dirty.
    #
    # Through `stageable` and not a second copy of its rule: what this refuses on
    # has to be exactly what `particle uncommitted --propose-commit` would stage,
    # or the seal refuses over a file the proposal never offers to commit.
    let loose = stageable (uncommitted-files $root)

    if ($loose | is-not-empty) and not $allow_untracked_particles {
        error make --unspanned {msg: $"the graph names bytes git does not track: ($loose | each {|r| $r.file | cwd-relative } | str join ', ') — the seal manifest walks `git ls-files`, so these would enter no root and the links naming them would be frozen pointing at nothing attested" help: "run `nu-cybergraph particle uncommitted --propose-commit` first, or seal with --allow-untracked-particles"}
    }

    # Number the provisional positions BEFORE the merkle run, so a position
    # enters the same root as the link record it counts: one seal, one
    # snapshot, one bundle. After it, the file staged below would still state
    # the claimed time, and the frozen proof would certify a time the graph
    # attests nothing about.
    #
    # This is the moment a claimed time becomes a number: the seal is the only
    # one that sees the whole run at once, and the only one a merge of two
    # checkouts has to pass through (_order.nu).
    let numbered = number-provisional $root

    let stage = (
        (signer-dirs $root) ++ ([$CERTS_DIR $SEALS_DIR $IMPORTED_DIR $RECEIPTS_DIR $ORDER_DIR] | each {|d| $root | path join $d })
    )
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
    # Upstream keeps both by default on purpose (nu-multiproof's `seal --no-content-anchor`) — an
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
    # A seal is finished here only once its snapshot exists, so the root the new
    # one supersedes is the newest snapshot, never the live statement: that can
    # be a draft an --external-signer run left waiting, or one a failed run left
    # behind. Superseding a draft would make it the `prev` of the next root with
    # no snapshot under it, and `seal chain` would refuse the graph for good.
    # Pinned by "a root replaced while it waits for its signature leaves the
    # seal chain whole".
    let snapshots = if (seals-dir $root | path exists) {
        ls (seals-dir $root) | where type == dir | get name | each { path join tree-root.txt }
    } else { [] }
    let supersedes = if ($snapshots | is-empty) { "genesis" } else {
        $snapshots | sort-by { merkle read-root $in | get seq } | last
    }

    let sealed = seal --repo $root --no-stamp=$no_stamp --no-content-anchor=(not $no_stamp) --response-file $response_file --external-signer=$external_signer --supersedes $supersedes

    # Why return before the snapshot: `seals/` is staged into the manifest, so a
    # snapshot written now — with no signature in it — would change the root the
    # second run computes, and the signature made over this run's statement would
    # be cleared as stale. Freezing certificates under a root nobody signed yet
    # would be worse. Pinned by "an external signer seal freezes nothing until
    # the signature arrives".
    if "awaiting_signature" in $sealed {
        return {sealed: $sealed}
    }
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
        # to be able to read what went wrong. Not a dead end, since this block
        # runs ahead of the freeze loops: no certificate names this root yet, so
        # the retry simply mints a new one.
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
    let newborn = link-files $root
        | where (not ((cert-path $root $it.signer $it.edge) | path exists))

    # `path expand` because this is a handle, not a label: `merkle prove` returns
    # its path relative to the cwd, and `move-file` must not depend on where the
    # operator happened to stand. The expand is the exact inverse — it resolves
    # against that same cwd — so it is a no-op on the absolute form.
    for l in $newborn {
        let proof = merkle prove ($l.file | path relative-to $root) --repo $root | path expand

        # certs mirror the link layout, so the certificate's own signer
        # directory may not exist yet — `mv` needs the parent standing.
        mkdir (certs-dir $root | path join $l.signer)
        move-file $proof (cert-path $root $l.signer $l.edge)
    }

    # Same freeze rule for custody receipts, resting on the same sweep: the FIRST
    # seal that catalogues a receipt sets its earliest provable custody bound, so
    # its proof freezes beside it and later seals must not touch it.
    # (*.receipt.cert.json does not end with .receipt.json — the suffix skips
    # already-frozen proofs.)
    let new_receipts = receipt-files $root
        | where (not ((receipt-cert-path $root $it.author $it.edge) | path exists))

    for r in $new_receipts {
        let proof = merkle prove ($r.file | path relative-to $root) --repo $root | path expand

        # The frozen proof lands beside its receipt, in the same author
        # directory — the parent already exists.
        move-file $proof (receipt-cert-path $root $r.author $r.edge)
    }

    # And the positions, third time the same rule: the first seal that
    # catalogues a number is what makes it provable, so its proof freezes
    # beside it and the number stops moving. (*.order.cert.json does not end
    # with .order.json — the suffix skips already-frozen proofs.)
    let new_positions = order-files $root
        | where (not ((order-cert-path $root $it.signer $it.edge) | path exists))

    for p in $new_positions {
        let proof = merkle prove ($p.file | path relative-to $root) --repo $root | path expand

        # The frozen proof lands beside its position, in the same signer
        # directory — the parent already exists.
        move-file $proof (order-cert-path $root $p.signer $p.edge)
    }

    let out = {
        sealed: $sealed
        newborn: ($newborn | length)
        receipts: ($new_receipts | length)
        positions: ($new_positions | length)
        numbered: $numbered
        snapshot: ($snap | cwd-relative)
    }

    # Last, so the buffer holds a proposal for a seal that finished — and so the
    # counts it states are the ones the freeze loops actually reached. Outside a
    # REPL this is harmless rather than a no-op: `commandline edit` writes the
    # engine's repl buffer unconditionally and only the REPL reads it back, so
    # the flag is inert in a script without being an error there.
    #
    # `own-signer` is called only here. `seal` has already refused an empty trust
    # list above, and upstream refuses an unregistered signing key before it
    # rewrites anything, so this resolves an identity both checks have passed —
    # it is the proposal's own need, not a third gate.
    if $propose_commit {
        # No --replace: it is `commandline edit`'s documented default, so naming
        # it would imply a choice among its four modes. The one that must never
        # appear here is --accept, which runs the buffer immediately — the
        # opposite of the guarantee this flag exists for.
        commandline edit (seal-commit-line $out $root (own-signer $root))
    }

    $out
}

# The seal chain, oldest first — one row per snapshot under seals/.
#
# Why this lives here and not in nu-multiproof: a repo there keeps only the LIVE
# statement, so nothing upstream can see more than one link of the chain. This
# repo keeps every seal it ever minted, because a birth certificate has to stay
# verifiable against the seal it was born under — so it is the only place the
# run of numbers can actually be checked.
#
# Two things are checked, and a break is an error rather than a false column:
# the seq values must run 0..N with no gap, and each statement's `prev` must be
# the root of the seal before it. A gap means a snapshot directory is missing —
# certificates born under it can no longer be verified — and that is a fact
# about the repo, not about the row it is discovered on.
@example "list the seal chain" { nu-cybergraph seal chain }
export def chain [
    --repo: path # Repo root (default: the nearest dir holding cybergraph/, up to the git root)
]: nothing -> table {
    let root = graph-root $repo
    let dir = seals-dir $root

    if not ($dir | path exists) {
        error make {msg: $"no seals/ directory at ($dir) — either this graph was never sealed, or the snapshots were removed and every certificate here verifies against nothing"}
    }
    # Read through nu-multiproof's own reader, never a second copy of the
    # statement regex: the format is upstream's to define.
    let rows = ls $dir
        | where type == dir
        | get name
        | each { merkle read-root ($in | path join "tree-root.txt") }
        | sort-by seq

    for i in 0..<($rows | length) {
        let row = $rows | get $i

        if $row.seq != $i {
            error make {msg: $"seal chain breaks at seq ($row.seq): expected ($i) — a snapshot under seals/ is missing, and every certificate born under it verifies against nothing"}
        }
        let expected_prev = if $i == 0 { "genesis" } else { ($rows | get ($i - 1)).root }

        if $row.prev != $expected_prev {
            error make {msg: $"seal ($row.seq) supersedes ($row.prev) but the seal before it is ($expected_prev) — the chain forks here"}
        }
    }
    $rows
}
