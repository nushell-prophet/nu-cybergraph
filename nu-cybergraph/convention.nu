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
#   confirm (edge)      {op: confirm}                                 → {cid_from: A, cid_to: B}
#   confirm (cyberlink) {op: confirm}                                 → {cid_from: A, cid_to: B, signer: S}
#   deny (edge)         {op: deny}                                    → {cid_from: A, cid_to: B}
#   deny (cyberlink)    {op: deny}                                    → {cid_from: A, cid_to: B, signer: S}
#   agree / disagree    {op: agree}                                   → B
#   quote               {about: A, op: quote}                         → B
#   translation         {about: A, op: translation}                   → B
#   pro / con           {about: C, op: pro}                           → B
#   question            {about: B, op: question}                      → Q
#   author              {about: B, op: author}                        → P
#   same                {about: P1, op: same}                         → P2
#   update              {cid_from: A, cid_to: B, op: update}          → C
#   update-file         {about: B, op: update}                        → C
#   answer              {cid_from: {about: B, op: question}, cid_to: Q, op: answer} → A
#   claimed-at          {about: X, op: claimed_at}                    → T
#
# Sixteen verbs, twelve conventions: repeat is bj002's edge repetition, which
# is not one of them (no CID in the source), and claimed-at, update-file and
# translation are this repo's extensions — claimed-at took over the claimed_at
# field removed from the link record, so a time claim is an ordinary optional
# edge instead of a fixture of every record; update-file is bj002's update act
# stated about a particle instead of an edge, which is what a version chain of
# particles needs; translation names the one relation a multilingual corpus lives on, and
# neither `same` nor `quote` says it. bj002's set of conventions is open, which
# is what permits all three.
#
# Reading these edges back is `link list` / `touching` / `tally` (link.nu,
# _read.nu): the published preimage is what makes a derived CID readable, so
# the writing side here and the reading side there are two halves of one
# mechanism. The rule they share: repeats and confirms are two signals, so a
# reader reports two numbers and never their sum — bj002's formula keeps them
# apart as f(repeats, confirms, denies, signer_weights, time_decay).
# Instructions force the distinction: several signers can propose an update
# from the one source {cid_from: A, cid_to: B, op: update}, and repetitions
# cannot pick between their versions, because repeating someone else's update
# claims you derived it yourself. Confirmations are what tell the proposals
# apart.

use _repo.nu graph-root
use _derive.nu [ record-bytes ]
use _particle.nu [ particle-store resolve-particle store-index ]
use _signer.nu [ own-signer ]
use _validate.nu [ RFC3339_RE ]
use link.nu

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
# `index` is built once by `edge` and threaded through the recursion — a
# convention can nest several operands (`answer` embeds a whole question
# record), and rebuilding it per operand is the scan-per-lookup cost
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
    # behind when the repo cannot name one. Resolved here and passed down, so
    # `link add` takes it as given rather than asking a second time.
    let signer_cid = if $signer != null { $signer } else { own-signer $root }
    let index = store-index $root
    link add (address $root $index $src $allow_missing $literal) (address $root $index $tgt $allow_missing $literal) --signer $signer_cid --repo $repo --allow-missing
}

# What `confirm` and `deny` speak about: the fields of the edge itself, plus
# its signer when a specific cyberlink rather than the edge is meant. The two
# verbs take the same three arguments and differ only in the op word — one
# shape, so it is built once.
def subject [cid_from: string cid_to: string about_signer: any]: nothing -> record {
    let pair = {cid_from: $cid_from cid_to: $cid_to}
    if $about_signer == null { $pair } else { $pair | insert signer $about_signer }
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

# Confirm an edge (`confirm A B`) or a specific cyberlink (`confirm A B S`).
# Source is the fixed record {op: confirm}; the target is what is supported —
# an address record carrying the real fields of the edge, plus its signer when
# a specific record is called valid (say, not spam), with no opinion about the
# statement. The mirror of `deny` in both targets; unlike `repeat`, it claims
# no work of one's own (bj002 "Confirming an edge and a cyberlink").
@example "confirm the edge A → B" { convention confirm QmA… QmB… }
@example "confirm signer S's cyberlink A → B" { convention confirm QmA… QmB… QmS… }
export def confirm [
    cid_from: string # source of the edge being confirmed
    cid_to: string # target of the edge being confirmed
    confirmed_signer?: string # signer of the cyberlink being confirmed; omit to confirm the edge itself
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {op: "confirm"} (subject $cid_from $cid_to $confirmed_signer) $signer $repo $allow_missing $literal
}

# Deny an edge (`deny A B`) or a specific cyberlink (`deny A B S`). Source is
# the fixed record {op: deny}; the target is what is disputed — an address
# record carrying the real fields of the disputed edge, plus its signer when a
# cyberlink is disputed (bj002 "Denying an edge and a cyberlink").
@example "deny the edge A → B" { convention deny QmA… QmB… }
@example "deny signer S's cyberlink A → B" { convention deny QmA… QmB… QmS… }
export def deny [
    cid_from: string # source of the disputed edge
    cid_to: string # target of the disputed edge
    disputed_signer?: string # signer of the disputed cyberlink; omit to deny the edge itself
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {op: "deny"} (subject $cid_from $cid_to $disputed_signer) $signer $repo $allow_missing $literal
}

# Update an edge: {cid_from: A, cid_to: B, op: update} → C marks C as the new
# target of the edge A → B. The record embeds the edge's own fields; updates
# reissue from the same source, so the latest is the current version
# (bj002 "Updating a previously published edge").
@example "update edge A → B to point at C" { convention update QmA… QmB… QmC… }
export def update [
    cid_from: string # source of the original edge
    cid_to: string # original target being replaced
    cid_new: string # the new target
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {cid_from: $cid_from cid_to: $cid_to op: "update"} $cid_new $signer $repo $allow_missing $literal
}

# Update a file: {about: B, op: update} → C — "C is the version that replaces B".
# bj002's `update` states the same act, "C replaces B", with A supplying the
# context of an edge; this is that act about the file alone, so a version chain
# of files gets an address of its own instead of being a plain edge no reader can
# tell from any other. The operand sits in the source, like quote/pro/con/
# question/author: reading B a reader computes one hash and reads outgoing edges,
# competing replacements share one address, and a replacement is itself
# replaceable — which is what makes the chain. Same op word as `update` because it
# is the same act; the record shape carries the arity, so the two addresses cannot
# collide. Not among bj002's twelve — an extension like `claimed-at`, which the
# open set of conventions permits (bj002 "Updating a previously published edge").
#
# Direction: source is the version being replaced, not the newest one. A chain
# written the other way round would need the reader to know the newest CID before
# it could ask what came before — the opposite of the query this exists for.
@example "C is the version that replaces B" { convention update-file QmB… QmC… }
export def "update-file" [
    superseded: string # the version being replaced
    replacement: string # the version replacing it
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $superseded op: "update"} $replacement $signer $repo $allow_missing $literal
}

# Quote: {about: A, op: quote} → B states that B is a faithful excerpt of A
# (content(B) is a substring of content(A), independently verifiable — this
# layer does not check it) (bj002 "Quotes").
@example "B is an excerpt of A" { convention quote QmA… QmB… }
export def quote [
    about: string # the quoted source
    excerpt: string # the excerpt
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $about op: "quote"} $excerpt $signer $repo $allow_missing $literal
}

# Translation: {about: A, op: translation} → B states that B says in another
# language what A says. The source is the original, so a reader holding it
# computes one hash and asks which translations exist; the direction also
# records which text came first, which a symmetric relation would lose.
#
# Not `same`: that says two names denote one entity, and two language versions
# are two particles, each with its own author and its own CID. Not `quote` either —
# a quote is checkable byte-for-byte, a translation is a judgement, and the
# signature is what puts the signer behind it. An extension like `claimed-at`
# and `update-file`, which bj002's open set of conventions permits.
@example "B is a translation of A" { convention translation QmA… QmB… }
export def translation [
    original: string # the text translated from
    translated: string # the text translated into another language
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $original op: "translation"} $translated $signer $repo $allow_missing $literal
}

# Agree: {op: agree} → B — "claim B is true". Gives an opinion about a
# standalone particle an edge of its own, so it aggregates like any other
# (bj002 "Agreement and disagreement with content").
@example "agree with claim B" { convention agree QmB… }
export def agree [
    cid: string # the particle being agreed with
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {op: "agree"} $cid $signer $repo $allow_missing $literal
}

# Disagree: {op: disagree} → B — "claim B is false". The other axis from
# deny: this speaks about the particle's content, deny about the statement or the record
# (bj002 "Agreement and disagreement with content").
@example "disagree with claim B" { convention disagree QmB… }
export def disagree [
    cid: string # the particle being disagreed with
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {op: "disagree"} $cid $signer $repo $allow_missing $literal
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

# Answer: {cid_from: {about: B, op: question}, cid_to: Q, op: answer} → A —
# "A answers the question Q about B". The record embeds the question edge's
# fields (the same move as update), so the answer attaches to the
# question-in-context, not the bare Q — one Q asked about different Bs does
# not glue answers together (bj002 "Question and answer").
@example "A answers question Q about B" { convention answer QmB… QmQ… QmA… }
export def answer [
    about: string # what the question is about
    question: string # the question content
    answer: string # the answer content
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {cid_from: {about: $about op: "question"} cid_to: $question op: "answer"} $answer $signer $repo $allow_missing $literal
}

# Authorship: {about: B, op: author} → P — "the author of particle B is P". The
# signer of the edge is the one who ports it (the archivist), which need not be
# the author P; the signature certifies the porting, not the authorship
# (bj002 "Authorship: porting from other mediums").
@example "the author of B is P" { convention author QmB… QmP… }
export def author [
    content: string # the ported particle
    author_id: string # CID of the author's identifier
    --signer: string
    --repo: path
    --allow-missing # skip the local-file check on a CID operand (see resolve-particle)
    --literal # treat a content operand as literal even if it names a path (see resolve-arg-bytes)
]: nothing -> record {
    edge {about: $content op: "author"} $author_id $signer $repo $allow_missing $literal
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
# published file. The heir of the claimed_at field removed from the link
# record: as an edge the claim is optional and per-signer, and the act keeps one
# CID for everyone. Claimed or in-record, the time stays unproven either way —
# the provable bound is the OTS anchor of the birth seal (README, time
# semantics).
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
    # The discipline the link record used to enforce on the field, now at the
    # one spot time claims are born: RFC 3339 shape (constrained charset — the
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
