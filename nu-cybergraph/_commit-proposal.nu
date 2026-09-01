# The `git commit` a freshly sealed graph should be committed with, written for
# a human to read and edit before running it.
#
# Why a proposal and not a commit: `seal` deliberately stops short of committing
# — the decision is the operator's, with context the pipeline does not have:
# message, scope, timing. What was missing is not the decision but the wording.
# A seal committed under "wip", or spread over three commits, makes the log
# useless for the one question it should answer: when was this root sealed, and
# what froze under it.
#
# Its own copy of nu-multiproof's `_commit-proposal.nu` rather than an import of
# it: a cybergraph seal commits a different set of directories, and the body has
# to state what has no counterpart upstream — the certificates this seal froze
# and the snapshot they verify against. Importing another project's `_`-internal
# would also take a compatibility promise nobody made, the same line `_signer.nu`
# drew for `resolve-key`.

use _layout.nu [ snapshot-dir signer-dirs CERTS_DIR SEALS_DIR IMPORTED_DIR RECEIPTS_DIR ORDER_DIR ]

# Quote a value for the Nushell block the caller is handed.
#
# `to nuon` IS Nushell's own string literal syntax, so its serializer already
# owns the job of staying in step with the parser; a hand-written escaper covers
# what is needed today and rots silently when the parser gains a rule.
#
# It does NOT sanitize for display: a control character in a path reaches the
# prompt raw, so a graph home carrying ANSI escapes could repaint the line the
# operator is meant to read. Left as is — the path is one they chose, not
# attacker-supplied input. The guarantee is that the block PARSES as one command
# with one argument, never that it renders honestly.
#
# Real newlines become the two characters `\n` unless --multiline: a path that
# spans lines stays safely inside the quotes, but it would silently change how
# many lines the proposal occupies. The message body is the one place a newline
# is meant, and there it stays a newline.
export def quote-arg [s: string --multiline]: nothing -> string {
    let quoted = $s | to nuon

    if $multiline { $quoted } else { $quoted | str replace --all "\n" '\n' }
}

# "1 endorsement" / "2 endorsements". The body states counts in three places and
# a bare number reads as a field name typo in at least one of them.
def count-of [n: int noun: string]: nothing -> string {
    if $n == 1 { $"($n) ($noun)" } else { $"($n) ($noun)s" }
}

# Build the block from what `nu-cybergraph seal` returned.
#
# `signer` is passed in rather than read off a filename: identity here is the CID
# of the registered pubkey's bytes, and `_signer.nu own-signer` is the one place
# that derives it from key material.
export def seal-commit-line [
    result: record # what `nu-cybergraph seal` returned
    root: path # graph home the seal targeted
    signer: string # signer CID, resolved from key material
]: nothing -> string {
    let sealed = $result.sealed
    # Read from its own field, never derived from a proof path: this seal always
    # stamps with --no-content-anchor, so there is no content proof to derive a
    # bundle from, and the fallback would state "no anchors" for a seal that did
    # post an endorsement digest to a public calendar.
    let bundle = $sealed | get --optional bundle

    let subject = $"seal: graph catalogued at merkle root ($sealed.merkle_root | str substring 0..<8)"

    # Only endorsements are ever anchored here — `seal` passes
    # --no-content-anchor on every stamped run, one anchor by design. So upstream's
    # "content + N endorsements" form has no counterpart, and its absence is the
    # invariant rather than a case left unhandled.
    #
    # "pending" is stated rather than read: a proof is pending by construction the
    # moment the calendar accepts it, since a Bitcoin anchor is hours to days
    # away. So this claims nothing the seal did not just do.
    let anchor_line = if $bundle == null {
        "Anchors: none, sealed with --no-stamp"
    } else {
        let endorsements = $sealed | get --optional sig_ots | default [] | length
        $"Anchors: (count-of $endorsements 'endorsement'), pending until Bitcoin confirms"
    }

    let bundle_line = if $bundle == null { [] } else {
        [$"Bundle: ($bundle | path relative-to $root)"]
    }

    # What this seal froze, and it is stated even when nothing did. A repeated
    # seal legitimately certifies nothing new — it only re-attests what earlier
    # roots already carried — and a body that dropped the line there would read
    # as a forgotten field instead of that fact.
    let froze = [
        (if $result.newborn > 0 { count-of $result.newborn "birth certificate" })
        (if $result.receipts > 0 { count-of $result.receipts "receipt certificate" })
        (if $result.positions > 0 { count-of $result.positions "position proof" })
    ] | compact
    let froze_line = if ($froze | is-empty) {
        "Froze: nothing new — every link, position and receipt already had its certificate"
    } else {
        $"Froze: ($froze | str join ', ')"
    }

    # Why: the seal REWRITES position files — the claimed time the operator's
    # `link add` wrote is replaced by the number the run gives it — and the
    # commit this proposal writes is what carries those files. A body that did
    # not name the rewrite would offer the operator a commit whose diff it
    # never explained.
    #
    # Stated only when it happened, unlike the freeze line above: "numbered
    # nothing" is the ordinary re-seal and would be a constant.
    let numbered_line = if $result.numbered > 0 {
        [$"Numbered: (count-of $result.numbered "provisional position") — each stated the time it arrived, and this seal is where the run turns that into a number"]
    } else { [] }

    # Recomputed from the layout rather than taken from `$result.snapshot`: that
    # field is relative to wherever the seal was RUN from, and a commit body is
    # read from anywhere. Same rule as the bundle line above — repo-relative, so
    # it reads the same wherever the graph sits on disk.
    let snapshot = snapshot-dir $root $sealed.merkle_root | path relative-to $root

    # No "Snapshot of: <commit>" line, which upstream's proposal carries. A
    # cybergraph seal leaves fresh certificates and a fresh snapshot uncommitted
    # by construction — that is the reason this proposal exists — so the line
    # would read "plus uncommitted changes" on every seal, and a constant is not
    # information.
    let message = [
        $subject
        ""
        $"Root CID: ($sealed.root_cid)"
        $"Merkle root: ($sealed.merkle_root)"
        $"Signed by: ($signer)"
        $froze_line
        ...$numbered_line
        $"Snapshot: ($snapshot)"
        ...$bundle_line
        $anchor_line
    ] | str join "\n"

    # The directories `seal` owns end to end, plus `multiproofs/` where upstream's
    # seal wrote. Filtered by the same rule seal filters its own staging with:
    # `git add` fails on a pathspec matching nothing.
    #
    # Whole directories, not the paths in $result: a seal both writes and DELETES
    # inside them — upstream clears a signature over bytes the regen changed —
    # and a deletion appears in no result field. It is the set seal owns, which is
    # what makes the wholesale add exact here rather than an `add -A` in disguise.
    #
    # `particles/` is absent because seal does not stage it either: publishing
    # the bytes a link names is the operator's own act, and it has its own
    # commit — `particle uncommitted --propose-commit`, which has to run BEFORE the
    # seal for the manifest to cover them. Seal refuses when it has not.
    let staged = (
        (signer-dirs $root | each { path basename }) ++ [$CERTS_DIR $SEALS_DIR $IMPORTED_DIR $RECEIPTS_DIR $ORDER_DIR "multiproofs"]
    )
        | where {|d|
            let dir = $root | path join $d
            ($dir | path exists) and (ls $dir | is-not-empty)
        }

    # Why `git -C $repo`: the sealed graph need not be the shell's repo. `seal
    # --repo` can target another one, and even for the local graph a bare pathspec
    # resolves against the CWD, so it fails whenever the prompt sits elsewhere.
    # `--` because the pathspec is data.
    [
        $"let repo = (quote-arg $root)"
        $"let msg = (quote-arg $message --multiline)"
        ""
        $"git -C $repo add -- ($staged | str join ' ')"
        "git -C $repo commit -m $msg"
    ] | str join "\n"
}

# The commit for a store the graph has outgrown — the files `particle uncommitted`
# found untracked and reachable, staged and committed as their own act.
#
# Its own commit and not a line added to the seal's: the two answer different
# questions. A seal commit says when a root was minted and what froze under it;
# this one says which bytes the graph can now dereference. They also have to run
# in that order — the manifest walks `git ls-files`, so bytes staged after the
# seal are covered by nothing until the next one.
#
# The CIDs are listed rather than counted. A commit body is what an operator
# reads when asking later which bytes entered here, and the addresses are the
# only names these files have; a diff of a binary store answers nothing.
export def particle-commit-line [
    rows: table # stageable rows from `_uncommitted.nu uncommitted-files`
    root: path # graph home the store belongs to
]: nothing -> string {
    let staged = $rows | get file | each { path relative-to $root }

    let message = [
        $"particles: publish (count-of ($rows | length) 'file') the graph names"
        ""
        "Each is named by a link here, so the next seal catalogues the bytes a"
        "reader will dereference — the manifest is every git-tracked file under"
        "the graph home, and these were outside it."
        ""
        ...($rows | each {|r| $"($r.cid)  ($r.size)" })
    ] | str join "\n"

    # Bare paths in the pathspec, unlike the message: a store filename is a CID
    # and an optional alphanumeric extension by `store-cid`'s own rule, so it
    # holds no space, quote or glob character to protect. `--` still, because a
    # pathspec is data.
    [
        $"let repo = (quote-arg $root)"
        $"let msg = (quote-arg $message --multiline)"
        ""
        $"git -C $repo add -- ($staged | str join ' ')"
        "git -C $repo commit -m $msg"
    ] | str join "\n"
}
