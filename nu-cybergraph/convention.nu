# The twelve conventions of bj002 — encode an instruction for processing the
# cybergraph as an ordinary edge. Every convention is one statement in a tiny
# grammar, so they all compile to a single engine (`address` + `edge`); the
# verbs below differ only in the shape they declare. `repeat` is the exception
# that proves the rule: edge repetition puts no special CID in the source, so
# there is no string that would go into `hash()` and it is not a convention at
# all — but it is still an edge, so it rides the same engine.
#
# The grammar has one atom and one constructor. An **address expression** is
# either a leaf — an operand, given as a CID or as the content itself — or a
# record whose values are themselves expressions: a nested record resolves to
# its derived CID, so the final record is flat, and its canonical bytes (see
# _derive.nu) give the CID. Operands go through `resolve-particle` (a CID is
# checked against this repo's store and used as-is, any other text is
# published as a file and replaced by its CID), so a verb's arguments accept
# content as well as addresses; `--allow-missing` skips the check for a
# deliberate forward reference. The one string
# that is NOT an operand is the value of an `op` key: the single reserved
# position in the grammar, a word the format defines, used verbatim. That is
# the whole distinction the engine has to make, and it makes it in one place,
# which is why every verb below is a single call.
#
# Resolving an expression walks the tree; every record it passes
# through is published as a self-addressed file under particles/ —
# the record is its own preimage, dereferencing the CID yields named fields
# with the real operand CIDs (bj002 "Reading instructions"). This recursion
# is homoiconicity made executable — an instruction is built of the same
# fields as the cyberlink itself. It rests on the record form of `derive`,
# this repo's experiment (see _derive.nu), not on bj002's comma-join. The
# whole layer, as expressions:
#
#   repeat              A                                             → B
#   confirm-edge        {op: confirm_edge}                            → {cid_from: A, cid_to: B}
#   confirm-link        {op: confirm_link}                            → {cid_from: A, cid_to: B, signer: S}
#   deny-edge           {op: deny_edge}                               → {cid_from: A, cid_to: B}
#   deny-link           {op: deny_link}                               → {cid_from: A, cid_to: B, signer: S}
#   agree-particle      {op: agree_particle}                          → B
#   disagree-particle   {op: disagree_particle}                       → B
#   quote-particle      {about: A, op: quote_particle}                → B
#   translation-particle {about: A, op: translation_particle}         → B
#   pro / con           {about: C, op: pro}                           → B
#   question            {about: B, op: question}                      → Q
#   author-particle     {about: B, op: author_particle}               → P
#   same                {about: P1, op: same}                         → P2
#   update-edge         {about: {cid_from: A, cid_to: B}, op: update_edge} → C
#   update-particle     {about: B, op: update_particle}               → C
#   answer-edge         {about: {cid_from: {about: B, op: question}, cid_to: Q}, op: answer_edge} → A
#   claimed-at          {about: X, op: claimed_at}                    → T
#
# Two shapes, and no third. A verdict (confirm, deny, agree, disagree) has a
# fixed source, {op}, and its subject in the target. A relation has its subject
# in `about` and points at the other file; when the subject is an edge, `about`
# holds the edge's address, the same CID a verdict targets.
#
# Eighteen verbs for twelve conventions — confirm and deny are one convention
# each and two verbs each, one per subject. Four answer to no convention:
# repeat is bj002's edge repetition, which
# is not one of them (no CID in the source), and claimed-at, update-particle
# and translation-particle are this repo's extensions — claimed-at makes a time claim an
# ordinary optional edge instead of a fixture of every record; update-particle
# is bj002's update act
# stated about a particle instead of an edge, which is what a version chain of
# particles needs; translation-particle names the one relation a multilingual corpus lives on, and
# neither `same` nor `quote-particle` says it. bj002's set of conventions is open, which
# is what permits all three.
#
# An op word names its subject wherever the verb has one: confirm_edge /
# confirm_link, deny_edge / deny_link, update_edge / update_particle, and —
# with a single possible subject — agree_particle, disagree_particle,
# quote_particle, author_particle, translation_particle, answer_edge. The
# record shape does not: update_edge and update_particle share {about, op},
# so the subject shows only to a reader that dereferences `about`,
# and a CID is opaque: no tool can tell a particle CID from an edge address
# at write time unless the preimage already sits in the store. So the word is
# the one check that always works — `agree_particle → {cid_from, cid_to}` is
# visibly wrong the way a gender ending that disagrees with its noun is,
# without parsing the sentence; the redundancy is what carries the intent.
# Where a verb takes any CID on purpose the word stays bare — pro, con,
# question, same, claimed_at — so bare is the signal "any CID". Only repeat
# has no word at all, because it writes no source record. bj002 spells the
# same words since 2026-09-02; the addresses still differ, because bj002
# hashes a comma-join where this repo derives from a record, so no address
# here has ever matched one there.
#
# Reading these edges back is `link list` / `touching` / `tally` (link.nu,
# _read.nu): the published preimage is what makes a derived CID readable, so
# the writing side here and the reading side there are two halves of one
# mechanism. The rule they share: repeats and confirms are two signals, so a
# reader reports two numbers and never their sum — bj002's formula keeps them
# apart as f(repeats, confirms, denies, signer_weights, time_decay).
# Instructions force the distinction: several signers can propose an update
# from the one source {about: {cid_from: A, cid_to: B}, op: update_edge}, and repetitions
# cannot pick between their versions, because repeating someone else's update
# claims you derived it yourself. Confirmations are what tell the proposals
# apart.

use _repo.nu graph-root
use _derive.nu [ record-bytes ]
use _particle.nu [ particle-store resolve-particle store-index ]
use _signer.nu [ resolve-signer ]
use _validate.nu [ RFC3339_RE ]
use link.nu
use _publish.nu [ publish-edge publish-link ]

# Re-exported so a reader can compute any address by hand: the edge address
# `derive {cid_from: A, cid_to: B}`, the cyberlink's derived CID
# `derive {cid_from: A, cid_to: B, signer: S}`, or a candidate instruction
# source (bj002 appendix, "Reading instructions").
export use _derive.nu [ derive ]

# Resolve an address expression to a CID. A leaf string is an operand —
# `resolve-particle` turns content into its CID and leaves a CID alone (or
# refuses it, unresolved locally, unless allow_missing). A record has its
# values resolved first (a nested record becomes its CID), except the `op`
# value, which is the format's own word and never an operand; the flat result
# is then published as a self-addressed file and its CID returned. The one
# place the grammar is interpreted.
#
# `index` is built once by the caller and threaded through the recursion —
# one call resolves every operand of the source and the target, and
# rebuilding it per operand is the scan-per-lookup cost
# `resolve-particle`'s own doc comment measures against.
def address [root: path index: record expr: any allow_missing: bool literal: bool]: nothing -> string {
    if ($expr | describe) == "string" { return (resolve-particle $root $index $expr --allow-missing=$allow_missing --literal=$literal) }
    let resolved = $expr | columns | reduce --fold {} {|key acc|
            $acc | insert $key (if $key == "op" { $expr.op } else { address $root $index ($expr | get $key) $allow_missing $literal })
        }

    record-bytes $resolved | particle-store $root
}

# Write a convention's edge: resolve the source and target expressions, then
# emit through `link add` so the triple guard, self-addressing and signer
# resolution all come from one place. The verbs forward their signer/repo/
# allow-missing controls here unchanged.
#
# `link add` gets --allow-missing unconditionally here, not $allow_missing:
# `address` above already resolved src/tgt down to CIDs that are guaranteed
# local (freshly published, or already checked against $allow_missing) — a
# second check on the same values in `link add` would be dead weight (another
# full index build) enforcing nothing the first check did not already settle.
def edge [
    src: any # source address expression
    tgt: any # target address expression
    signer: any # signer override or null
    repo: any # target repo or null
    allow_missing: bool # skip the local-file check on a CID operand
    literal: bool # treat a content operand as literal even if it names a path
]: nothing -> record {
    let root = graph-root $repo
    # Same order as `link add`, for the same reason: `address` publishes every
    # record it mints, so a signer resolved after it would leave those files
    # behind when the repo cannot name one. Through `resolve-signer` and not an
    # inline own-signer call, so a bare-string signer means the same thing on
    # both write paths. Resolved here and passed down as a CID, so `link add`
    # takes it as given rather than asking a second time.
    let signer_cid = resolve-signer $root $signer
    let index = store-index $root

    link add (address $root $index $src $allow_missing $literal) (address $root $index $tgt $allow_missing $literal) --signer $signer_cid --repo $repo --allow-missing
}

# Repeat an edge: state the same thing yourself. Both endpoints are leaves —
# a plain edge is not an instruction, and repetition writes no source record,
# so it is not a convention. What separates it from `confirm` is work: you
# collated the source, re-ran the computation, checked the quote — only then
# is repeating it honest, where `confirm` leans on whoever did that work
# (bj002 "Confirming an edge and a cyberlink").
@example "repeat the edge A → B" { convention repeat QmA… QmB… }
export def repeat [
    cid_from: string # source vertex of the edge being repeated
    cid_to: string # target vertex of the edge being repeated
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge $cid_from $cid_to $signer $repo $allow_missing $literal
}

# What the four verbs below speak about — the edge, or one signer's cyberlink —
# and the edge `update-edge` and `answer-edge` take as their subject, is
# published through `_publish.nu`, the bodies behind `particle add-edge` /
# `add-link`, and not by building the record here and letting `address`
# publish it. Those verbs mint exactly these two records, and a second
# construction site is how the two drifted: `address` resolves every value as
# an ordinary operand, so a cyberlink target demanded the SIGNER's bytes in
# particles/ — but a signer CID names a pubkey file, which lives in
# multiproofs/pubkeys/, and `_signer.nu` says plainly that a signer CID is
# never checked against the store because `own-signer`'s own answer would fail
# that check. One publisher, and the question cannot be answered two ways.
#
# The result is a CID that is local by construction, so `address` passes it
# through as a leaf and no verb needs a special case.
#
# Each resolves its own signer before publishing, rather than leaving it to
# `edge`: the publish call writes a file, and a signer resolved after it would
# leave that file behind when the repo cannot name one — `link add` states the
# same order for the same reason. `edge` re-resolves the CID it gets, which
# passes it through unchanged (resolve-signer).

# Confirm an edge: {op: confirm_edge} → {cid_from: A, cid_to: B} supports the
# statement A → B itself — it is true no matter who published it. The mirror
# of `deny-edge`; unlike `repeat`, it claims no work of one's own
# (bj002 "Confirming an edge and a cyberlink").
@example "confirm the edge A → B" { convention confirm-edge QmA… QmB… }
export def "confirm-edge" [
    cid_from: string # source of the edge being confirmed
    cid_to: string # target of the edge being confirmed
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    let root = graph-root $repo
    let signer_cid = resolve-signer $root $signer

    edge {op: "confirm_edge"} (publish-edge $root $cid_from $cid_to $allow_missing $literal) $signer_cid $repo $allow_missing $literal
}

# Confirm a cyberlink: {op: confirm_link} → {cid_from: A, cid_to: B, signer: S}
# calls S's record valid — say, not spam — with no opinion about the statement
# it makes. The mirror of `deny-link` (bj002 "Confirming an edge and a
# cyberlink").
@example "confirm signer S's cyberlink A → B" { convention confirm-link QmA… QmB… QmS… }
export def "confirm-link" [
    cid_from: string # source of the edge the cyberlink asserts
    cid_to: string # target of the edge the cyberlink asserts
    confirmed_signer: string # signer of the cyberlink being confirmed
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    let root = graph-root $repo
    let signer_cid = resolve-signer $root $signer

    edge {op: "confirm_link"} (publish-link $root $cid_from $cid_to $confirmed_signer $allow_missing $literal) $signer_cid $repo $allow_missing $literal
}

# Deny an edge: {op: deny_edge} → {cid_from: A, cid_to: B} disputes the
# statement A → B itself. The mirror of `confirm-edge`
# (bj002 "Denying an edge and a cyberlink").
@example "deny the edge A → B" { convention deny-edge QmA… QmB… }
export def "deny-edge" [
    cid_from: string # source of the disputed edge
    cid_to: string # target of the disputed edge
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    let root = graph-root $repo
    let signer_cid = resolve-signer $root $signer

    edge {op: "deny_edge"} (publish-edge $root $cid_from $cid_to $allow_missing $literal) $signer_cid $repo $allow_missing $literal
}

# Deny a cyberlink: {op: deny_link} → {cid_from: A, cid_to: B, signer: S}
# calls S's record invalid — say, spam — with no opinion about the statement
# it makes. The mirror of `confirm-link`
# (bj002 "Denying an edge and a cyberlink").
@example "deny signer S's cyberlink A → B" { convention deny-link QmA… QmB… QmS… }
export def "deny-link" [
    cid_from: string # source of the edge the disputed cyberlink asserts
    cid_to: string # target of the edge the disputed cyberlink asserts
    disputed_signer: string # signer of the disputed cyberlink
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    let root = graph-root $repo
    let signer_cid = resolve-signer $root $signer

    edge {op: "deny_link"} (publish-link $root $cid_from $cid_to $disputed_signer $allow_missing $literal) $signer_cid $repo $allow_missing $literal
}

# Update an edge: {about: {cid_from: A, cid_to: B}, op: update_edge} → C marks
# C as the new target of the edge A → B. The subject is the edge's address, so
# the act is tied to that edge and to no other; updates reissue from the same
# source, so the latest is the current version
# (bj002 "Updating a previously published edge").
@example "update edge A → B to point at C" { convention update-edge QmA… QmB… QmC… }
export def "update-edge" [
    cid_from: string # source of the original edge
    cid_to: string # original target being replaced
    cid_new: string # the new target
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    let root = graph-root $repo
    let signer_cid = resolve-signer $root $signer

    edge {about: (publish-edge $root $cid_from $cid_to $allow_missing $literal) op: "update_edge"} $cid_new $signer_cid $repo $allow_missing $literal
}

# Update a particle: {about: B, op: update_particle} → C — "C is the version
# that replaces B".
# bj002's `update_edge` states the same act, "C replaces B", with A supplying the
# context of an edge; this is that act about the particle alone, so a version chain
# of particles gets an address of its own instead of being a plain edge no reader can
# tell from any other. The operand sits in the source, like quote/pro/con/
# question/author: reading B a reader computes one hash and reads outgoing edges,
# competing replacements share one address, and a replacement is itself
# replaceable — which is what makes the chain. Not among bj002's twelve — an
# extension like `claimed-at`, which the open set of conventions permits
# (bj002 "Updating a previously published edge").
#
# Its own op word, not `update_edge`: both records have the one shape
# {about, op}, and what `about` names — an edge address or a particle — shows
# only to a reader that dereferences it. The word is what keeps the two acts
# apart, in the address and in `link list`'s op column alike.
#
# Direction: source is the version being replaced, not the newest one. A chain
# written the other way round would need the reader to know the newest CID before
# it could ask what came before — the opposite of the query this exists for.
@example "C is the version that replaces B" { convention update-particle QmB… QmC… }
export def "update-particle" [
    superseded: string # the version being replaced
    replacement: string # the version replacing it
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $superseded op: "update_particle"} $replacement $signer $repo $allow_missing $literal
}

# Quote: {about: A, op: quote_particle} → B states that B is a faithful excerpt of A
# (content(B) is a substring of content(A), independently verifiable — this
# layer does not check it) (bj002 "Quotes").
@example "B is an excerpt of A" { convention quote-particle QmA… QmB… }
export def "quote-particle" [
    about: string # the quoted source
    excerpt: string # the excerpt
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $about op: "quote_particle"} $excerpt $signer $repo $allow_missing $literal
}

# Translation: {about: A, op: translation_particle} → B states that B says in another
# language what A says. The source is the original, so a reader holding it
# computes one hash and asks which translations exist; the direction also
# records which text came first, which a symmetric relation would lose.
#
# Not `same`: that says two names denote one entity, and two language versions
# are two particles, each with its own author and its own CID. Not `quote-particle` either —
# a quote is checkable byte-for-byte, a translation is a judgement, and the
# signature is what puts the signer behind it. An extension like `claimed-at`
# and `update-particle`, which bj002's open set of conventions permits.
@example "B is a translation of A" { convention translation-particle QmA… QmB… }
export def "translation-particle" [
    original: string # the text translated from
    translated: string # the text translated into another language
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $original op: "translation_particle"} $translated $signer $repo $allow_missing $literal
}

# Agree: {op: agree_particle} → B — "claim B is true". Gives an opinion about a
# standalone particle an edge of its own, so it aggregates like any other
# (bj002 "Agreement and disagreement with content").
@example "agree with claim B" { convention agree-particle QmB… }
export def "agree-particle" [
    cid: string # the particle being agreed with
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {op: "agree_particle"} $cid $signer $repo $allow_missing $literal
}

# Disagree: {op: disagree_particle} → B — "claim B is false". The other axis from
# deny: this speaks about the particle's content, deny about the statement or the record
# (bj002 "Agreement and disagreement with content").
@example "disagree with claim B" { convention disagree-particle QmB… }
export def "disagree-particle" [
    cid: string # the particle being disagreed with
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {op: "disagree_particle"} $cid $signer $repo $allow_missing $literal
}

# Argument for: {about: C, op: pro} → B — "B is an argument for C". C is any
# CID: a particle, an edge, or a cyberlink; the level of argumentation is the
# out-degree of the source (bj002 "Argument for and against").
@example "B argues for C" { convention pro QmC… QmB… }
export def pro [
    target: string # what the argument is for (any CID)
    argument: string # the argument content
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $target op: "pro"} $argument $signer $repo $allow_missing $literal
}

# Argument against: {about: C, op: con} → B — "B is an argument against C".
# The mirror of `pro` (bj002 "Argument for and against").
@example "B argues against C" { convention con QmC… QmB… }
export def con [
    target: string # what the argument is against (any CID)
    argument: string # the argument content
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $target op: "con"} $argument $signer $repo $allow_missing $literal
}

# Question: {about: B, op: question} → Q — "Q is a question about B". B is any
# CID; that Q is a question is visible from its content, so no separate mark
# (bj002 "Question and answer").
@example "Q is a question about B" { convention question QmB… QmQ… }
export def question [
    about: string # what the question is about (any CID)
    question: string # the question content
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $about op: "question"} $question $signer $repo $allow_missing $literal
}

# Answer: {about: {cid_from: {about: B, op: question}, cid_to: Q}, op: answer_edge}
# → A — "A answers the question Q about B". The subject is the address of the
# question edge (the same move as update), so the answer attaches to the
# question-in-context, not the bare Q — one Q asked about different Bs does
# not glue answers together (bj002 "Question and answer").
@example "A answers question Q about B" { convention answer-edge QmB… QmQ… QmA… }
export def "answer-edge" [
    about: string # what the question is about
    question: string # the question content
    answer: string # the answer content
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    let root = graph-root $repo
    let signer_cid = resolve-signer $root $signer
    let asked = address $root (store-index $root) {about: $about op: "question"} $allow_missing $literal

    edge {about: (publish-edge $root $asked $question $allow_missing $literal) op: "answer_edge"} $answer $signer_cid $repo $allow_missing $literal
}

# Authorship: {about: B, op: author_particle} → P — "the author of particle B is P". The
# signer of the edge is the one who ports it (the archivist), which need not be
# the author P; the signature certifies the porting, not the authorship
# (bj002 "Authorship: porting from other mediums").
@example "the author of B is P" { convention author-particle QmB… QmP… }
export def "author-particle" [
    content: string # the ported particle
    author_id: string # CID of the author's identifier
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $content op: "author_particle"} $author_id $signer $repo $allow_missing $literal
}

# Identity: {about: P1, op: same} → P2 — "P1 and P2 name one entity" (the
# analogue of owl:sameAs). Directed: the mirror edge is a different pair,
# counted separately; folding directions is a read policy (bj002 "Identity:
# another name for the same entity").
@example "P1 and P2 are the same entity" { convention same QmP1… QmP2… }
export def same [
    name_from: string # one name of the entity
    name_to: string # another name of the same entity
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $name_from op: "same"} $name_to $signer $repo $allow_missing $literal
}

# Claimed time: {about: X, op: claimed_at} → T — "I claim X's time is T". X is
# any CID: a link file (= the triple), an edge or cyberlink derived CID, or a
# published file. As an edge the claim is optional and per-signer, and the act
# keeps one CID for everyone. Claimed or in-record, the time stays unproven
# either way — the provable bound is the OTS anchor of the birth seal (README,
# time semantics).
@example "claim when an act happened" { convention claimed-at QmX… "2026-07-16T00:00:00+00:00" }
export def claimed-at [
    about: string # the CID whose time is claimed
    timestamp?: string # RFC 3339 claimed time (default: now, UTC)
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    let t = if $timestamp != null { $timestamp } else {
        date now | date to-timezone UTC | format date "%+"
    }

    # Checked at the one spot time claims are born: RFC 3339 shape (constrained charset — the
    # timestamp file stays escape-free), then a real calendar date (the regex
    # admits month 13, `into datetime` rejects it).
    if $t !~ $RFC3339_RE {
        error make {msg: $"claimed time is not an RFC 3339 timestamp: ($t | to json)"}
    }
    try { $t | into datetime | ignore } catch {
        error make {msg: $"claimed time is not a real calendar date: ($t | to json)"}
    }
    edge {about: $about op: "claimed_at"} $t $signer $repo $allow_missing $literal
}
