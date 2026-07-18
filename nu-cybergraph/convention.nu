# The twelve conventions of bj002 — encode an instruction for processing the
# cybergraph as an ordinary edge. Every convention is the same move: build a
# derived source CID with `derive`, then write the edge through `link add`, so
# the triple guard, self-addressing, timestamps and neuron resolution all come
# from one place. The verbs differ only in how they shape the source.
#
# Every derived CID this layer mints is also published as a preimage particle
# under particles/ (bj002 "Reading instructions"): the string "update,Qm…" is
# written to a file named by its own CID, so a reader who sees the opaque
# source of an edge can dereference it and recognise the instruction. Nested
# forms publish every link of the chain — for `answer`, the question address
# and the question-edge address as well as the answer source.
#
# Reading and aggregation (count confirms, weigh neurons, read consensus) are
# deliberately out of scope: a local repo is a single neuron, so there is
# nothing to aggregate yet. `derive` alone gives a reader the address to look
# up; the counting is a later, cross-neuron concern.

use _repo.nu graph-root
use _layout.nu [particles-dir particle-path]
use _derive.nu [derive preimage]
use link.nu

# Re-exported so a reader can compute any address by hand: the edge address
# `derive $from $to`, the cyberlink's derived CID `derive $from $to $neuron`,
# or a candidate instruction source (bj002 appendix, "Reading instructions").
export use _derive.nu [derive]

# Publish the preimage of a derived CID as a self-addressed particle and return
# the CID. Idempotent: identical content is one particle (same CID = same
# bytes), so an already-present file is left untouched rather than rewritten.
def publish [root: path ...args: string]: nothing -> string {
    let cid = derive ...$args
    mkdir (particles-dir $root)
    let out = particle-path $root $cid
    if not ($out | path exists) {
        preimage ...$args | into binary | save --raw $out
    }
    $cid
}

# Write the convention's edge. Thin pass-through to `link add` so every
# convention shares one record path; forwards the author/time/repo controls.
def emit [
    source: string
    target: string
    neuron: any # author override or null
    claimed_at: any # claimed timestamp or null
    repo: any # target repo or null
    reassert: bool
]: nothing -> record {
    link add $source $target --neuron $neuron --claimed-at $claimed_at --repo $repo --reassert=$reassert
}

# Confirm an edge: simply repeat it. No special source and no preimage — a
# plain edge is not an instruction; the repetition itself is what aggregation
# counts (bj002 "Confirming an edge").
@example "confirm the edge A → B" { convention confirm QmA… QmB… }
export def confirm [
    cid_from: string # source particle of the edge being confirmed
    cid_to: string # target particle of the edge being confirmed
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    emit $cid_from $cid_to $neuron $claimed_at $repo $reassert
}

# Deny an edge (`deny A B`) or a specific cyberlink (`deny A B N`). Source is
# the fixed CID hash("deny"); the target is what is disputed — the edge address
# hash(A,B), or the cyberlink's derived CID hash(A,B,N) when a disputed neuron
# is given (bj002 "Denying an edge and a cyberlink").
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
    let source = publish $root "deny"
    let target = if $disputed_neuron != null {
        publish $root $cid_from $cid_to $disputed_neuron
    } else {
        publish $root $cid_from $cid_to
    }
    emit $source $target $neuron $claimed_at $repo $reassert
}

# Update an edge: hash("update", hash(A, B)) → C marks C as the new target of
# the edge A → B. Updates reissue from the same source, so the latest is the
# current version (bj002 "Updating a previously published edge").
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
    let edge = publish $root $cid_from $cid_to
    let source = publish $root "update" $edge
    emit $source $cid_new $neuron $claimed_at $repo $reassert
}

# Quote: hash("quote", A) → B states that B is a faithful excerpt of A
# (content(B) is a substring of content(A), independently verifiable — this
# layer does not check it) (bj002 "Quotes").
@example "B is an excerpt of A" { convention quote QmA… QmB… }
export def quote [
    cid_from: string # the quoted source
    cid_to: string # the excerpt
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    let source = publish $root "quote" $cid_from
    emit $source $cid_to $neuron $claimed_at $repo $reassert
}

# Agree: hash("agree") → B — "claim B is true". Gives an opinion about
# standalone content an edge of its own, so it aggregates like any other
# (bj002 "Agreement and disagreement with content").
@example "agree with claim B" { convention agree QmB… }
export def agree [
    cid: string # the content being agreed with
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    emit (publish $root "agree") $cid $neuron $claimed_at $repo $reassert
}

# Disagree: hash("disagree") → B — "claim B is false". The other axis from
# deny: this speaks about the content, deny about the statement or the record
# (bj002 "Agreement and disagreement with content").
@example "disagree with claim B" { convention disagree QmB… }
export def disagree [
    cid: string # the content being disagreed with
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    let root = graph-root $repo
    emit (publish $root "disagree") $cid $neuron $claimed_at $repo $reassert
}

# Argument for: hash("pro", C) → B — "B is an argument for C". C is any CID:
# content, an edge, or a cyberlink; the level of argumentation is the
# out-degree of hash("pro", C) (bj002 "Argument for and against").
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
    emit (publish $root "pro" $target) $argument $neuron $claimed_at $repo $reassert
}

# Argument against: hash("con", C) → B — "B is an argument against C". The
# mirror of `pro` (bj002 "Argument for and against").
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
    emit (publish $root "con" $target) $argument $neuron $claimed_at $repo $reassert
}

# Question: hash("question", B) → Q — "Q is a question about B". B is any CID;
# that Q is a question is visible from its content, so no separate mark
# (bj002 "Question and answer").
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
    emit (publish $root "question" $about) $question $neuron $claimed_at $repo $reassert
}

# Answer: hash("answer", hash(hash("question", B), Q)) → A — "A answers the
# question Q about B". The answer attaches to the question-in-context (the
# question edge's address), not the bare Q, so one Q asked about different Bs
# does not glue answers together (bj002 "Question and answer").
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
    let q_source = publish $root "question" $about
    let q_edge = publish $root $q_source $question
    let source = publish $root "answer" $q_edge
    emit $source $answer $neuron $claimed_at $repo $reassert
}

# Authorship: hash("author", B) → P — "the author of content B is P". The
# neuron of the edge is the one who ports it (the archivist), which need not be
# the author P; the signature certifies the porting, not the authorship
# (bj002 "Authorship: porting from other mediums").
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
    emit (publish $root "author" $content) $author_id $neuron $claimed_at $repo $reassert
}

# Identity: hash("same", P1) → P2 — "P1 and P2 name one entity" (the analogue
# of owl:sameAs). Directed: the mirror edge is a different pair, counted
# separately; folding directions is a read policy (bj002 "Identity").
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
    emit (publish $root "same" $name_from) $name_to $neuron $claimed_at $repo $reassert
}
