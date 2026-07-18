# The twelve conventions of bj002-1 — encode an instruction for processing the
# cybergraph as an ordinary edge. Every convention is one statement in a tiny
# grammar, so they all compile to a single engine (`address` + `edge`); the
# verbs below differ only in the shape they declare.
#
# The grammar has one atom and one constructor. An **address expression** is
# either a leaf — a CID you supply or an op word ("deny"), used verbatim — or
# a record whose values are themselves expressions: a nested record resolves
# to its derived CID, so the final record is flat, and its canonical bytes
# (see _derive.nu) give the CID. A verb's positional arguments accept content
# as well as CIDs: each verb passes them through `resolve-particle` first (a
# CID is used as-is, any other text is published as a content particle and
# replaced by its CID), so by the time an expression is built every leaf is a
# CID or an op word. Resolving an expression walks the tree; every record it
# passes through is published as a self-addressed particle under particles/ —
# the record is its own preimage, dereferencing the CID yields named fields
# with the real operand CIDs (bj002-1 "Reading instructions"). This recursion
# is the homoiconicity bj002-1 describes made executable — an instruction is
# built of the same fields as the cyberlink itself. The whole layer, as
# expressions:
#
#   confirm            A                                             → B
#   deny (edge)        {op: deny}                                    → {cid_from: A, cid_to: B}
#   deny (cyberlink)   {op: deny}                                    → {cid_from: A, cid_to: B, neuron: N}
#   agree / disagree   {op: agree}                                   → B
#   quote              {about: A, op: quote}                         → B
#   pro / con          {about: C, op: pro}                           → B
#   question           {about: B, op: question}                      → Q
#   author             {about: B, op: author}                        → P
#   same               {about: P1, op: same}                         → P2
#   update             {cid_from: A, cid_to: B, op: update}          → C
#   answer             {cid_from: {about: B, op: question}, cid_to: Q, op: answer} → A
#
# Reading and aggregation (count confirms, weigh neurons, read consensus) are
# deliberately out of scope: a local repo is a single neuron, so there is
# nothing to aggregate yet. `derive` alone gives a reader the address to look
# up; the counting is a later, cross-neuron concern.

use _repo.nu graph-root
use _derive.nu [record-bytes]
use _particle.nu [particle-store resolve-particle]
use link.nu

# Re-exported so a reader can compute any address by hand: the edge address
# `derive {cid_from: A, cid_to: B}`, the cyberlink's derived CID
# `derive {cid_from: A, cid_to: B, neuron: N}`, or a candidate instruction
# source (bj002-1 appendix, "Reading instructions").
export use _derive.nu [derive]

# Resolve an address expression to a CID. A leaf string is used verbatim (a
# CID input or an op word); a record has its values resolved first — a nested
# record becomes its CID — then its canonical bytes are published as a
# self-addressed particle and the particle's CID returned. The one place the
# grammar is interpreted.
def address [root: path expr: any]: nothing -> string {
    if ($expr | describe) == "string" { return $expr }
    let resolved = $expr | columns | reduce --fold {} {|key acc|
        $acc | insert $key (address $root ($expr | get $key))
    }
    record-bytes $resolved | particle-store $root
}

# Write a convention's edge: resolve the source and target expressions, then
# emit through `link add` so the triple guard, self-addressing and author/time
# resolution all come from one place. The verbs forward their author/time/repo
# controls here unchanged.
def edge [
    src: any # source address expression
    tgt: any # target address expression
    neuron: any # author override or null
    claimed_at: any # claimed timestamp or null
    repo: any # target repo or null
    reassert: bool
]: nothing -> record {
    let root = graph-root $repo
    link add (address $root $src) (address $root $tgt) --neuron $neuron --claimed-at $claimed_at --repo $repo --reassert=$reassert
}

# Confirm an edge: simply repeat it. Both endpoints are leaves — a plain edge
# is not an instruction, and the repetition itself is what aggregation counts
# (bj002-1 "Confirming an edge").
@example "confirm the edge A → B" { convention confirm QmA… QmB… }
export def confirm [
    cid_from: string # source particle of the edge being confirmed
    cid_to: string # target particle of the edge being confirmed
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    let cid_from = resolve-particle $root $cid_from
    let cid_to = resolve-particle $root $cid_to
    edge $cid_from $cid_to $neuron $claimed_at $repo $reassert
}

# Deny an edge (`deny A B`) or a specific cyberlink (`deny A B N`). Source is
# the fixed record {op: deny}; the target is what is disputed — an address
# record carrying the real fields of the disputed edge, plus its neuron when a
# cyberlink is disputed (bj002-1 "Denying an edge and a cyberlink").
@example "deny the edge A → B" { convention deny QmA… QmB… }
@example "deny neuron N's cyberlink A → B" { convention deny QmA… QmB… QmN… }
export def deny [
    cid_from: string # source of the disputed edge
    cid_to: string # target of the disputed edge
    disputed_neuron?: string # neuron of the disputed cyberlink; omit to deny the edge itself
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    let disputed = {
        cid_from: (resolve-particle $root $cid_from)
        cid_to: (resolve-particle $root $cid_to)
    }
    let target = if $disputed_neuron == null { $disputed } else {
        $disputed | insert neuron (resolve-particle $root $disputed_neuron)
    }
    edge {op: "deny"} $target $neuron $claimed_at $repo $reassert
}

# Update an edge: {cid_from: A, cid_to: B, op: update} → C marks C as the new
# target of the edge A → B. The record embeds the edge's own fields; updates
# reissue from the same source, so the latest is the current version
# (bj002-1 "Updating a previously published edge").
@example "update edge A → B to point at C" { convention update QmA… QmB… QmC… }
export def update [
    cid_from: string # source of the original edge
    cid_to: string # original target being replaced
    cid_new: string # the new target
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    let src = {
        cid_from: (resolve-particle $root $cid_from)
        cid_to: (resolve-particle $root $cid_to)
        op: "update"
    }
    edge $src (resolve-particle $root $cid_new) $neuron $claimed_at $repo $reassert
}

# Quote: {about: A, op: quote} → B states that B is a faithful excerpt of A
# (content(B) is a substring of content(A), independently verifiable — this
# layer does not check it) (bj002-1 "Quotes").
@example "B is an excerpt of A" { convention quote QmA… QmB… }
export def quote [
    about: string # the quoted source
    excerpt: string # the excerpt
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    edge {about: (resolve-particle $root $about), op: "quote"} (resolve-particle $root $excerpt) $neuron $claimed_at $repo $reassert
}

# Agree: {op: agree} → B — "claim B is true". Gives an opinion about
# standalone content an edge of its own, so it aggregates like any other
# (bj002-1 "Agreement and disagreement with content").
@example "agree with claim B" { convention agree QmB… }
export def agree [
    cid: string # the content being agreed with
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    edge {op: "agree"} (resolve-particle (graph-root $repo) $cid) $neuron $claimed_at $repo $reassert
}

# Disagree: {op: disagree} → B — "claim B is false". The other axis from
# deny: this speaks about the content, deny about the statement or the record
# (bj002-1 "Agreement and disagreement with content").
@example "disagree with claim B" { convention disagree QmB… }
export def disagree [
    cid: string # the content being disagreed with
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    edge {op: "disagree"} (resolve-particle (graph-root $repo) $cid) $neuron $claimed_at $repo $reassert
}

# Argument for: {about: C, op: pro} → B — "B is an argument for C". C is any
# CID: content, an edge, or a cyberlink; the level of argumentation is the
# out-degree of the source (bj002-1 "Argument for and against").
@example "B argues for C" { convention pro QmC… QmB… }
export def pro [
    target: string # what the argument is for (any CID)
    argument: string # the argument content
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    edge {about: (resolve-particle $root $target), op: "pro"} (resolve-particle $root $argument) $neuron $claimed_at $repo $reassert
}

# Argument against: {about: C, op: con} → B — "B is an argument against C".
# The mirror of `pro` (bj002-1 "Argument for and against").
@example "B argues against C" { convention con QmC… QmB… }
export def con [
    target: string # what the argument is against (any CID)
    argument: string # the argument content
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    edge {about: (resolve-particle $root $target), op: "con"} (resolve-particle $root $argument) $neuron $claimed_at $repo $reassert
}

# Question: {about: B, op: question} → Q — "Q is a question about B". B is any
# CID; that Q is a question is visible from its content, so no separate mark
# (bj002-1 "Question and answer").
@example "Q is a question about B" { convention question QmB… QmQ… }
export def question [
    about: string # what the question is about (any CID)
    question: string # the question content
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    edge {about: (resolve-particle $root $about), op: "question"} (resolve-particle $root $question) $neuron $claimed_at $repo $reassert
}

# Answer: {cid_from: {about: B, op: question}, cid_to: Q, op: answer} → A —
# "A answers the question Q about B". The record embeds the question edge's
# fields (the same move as update), so the answer attaches to the
# question-in-context, not the bare Q — one Q asked about different Bs does
# not glue answers together (bj002-1 "Question and answer").
@example "A answers question Q about B" { convention answer QmB… QmQ… QmA… }
export def answer [
    about: string # what the question is about
    question: string # the question content
    answer: string # the answer content
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    let src = {
        cid_from: {about: (resolve-particle $root $about), op: "question"}
        cid_to: (resolve-particle $root $question)
        op: "answer"
    }
    edge $src (resolve-particle $root $answer) $neuron $claimed_at $repo $reassert
}

# Authorship: {about: B, op: author} → P — "the author of content B is P". The
# neuron of the edge is the one who ports it (the archivist), which need not be
# the author P; the signature certifies the porting, not the authorship
# (bj002-1 "Authorship: porting from other mediums").
@example "the author of B is P" { convention author QmB… QmP… }
export def author [
    content: string # the ported content
    author_id: string # CID of the author's identifier
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    edge {about: (resolve-particle $root $content), op: "author"} (resolve-particle $root $author_id) $neuron $claimed_at $repo $reassert
}

# Identity: {about: P1, op: same} → P2 — "P1 and P2 name one entity" (the
# analogue of owl:sameAs). Directed: the mirror edge is a different pair,
# counted separately; folding directions is a read policy (bj002-1 "Identity").
@example "P1 and P2 are the same entity" { convention same QmP1… QmP2… }
export def same [
    name_from: string # one name of the entity
    name_to: string # another name of the same entity
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    edge {about: (resolve-particle $root $name_from), op: "same"} (resolve-particle $root $name_to) $neuron $claimed_at $repo $reassert
}
