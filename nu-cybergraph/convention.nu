# The twelve conventions of bj002 — encode an instruction for processing the
# cybergraph as an ordinary edge. Every convention is one statement in a tiny
# grammar, so they all compile to a single engine (`address` + `edge`); the
# verbs below differ only in the shape they declare.
#
# The grammar has one atom and one constructor. An **address expression** is
# either a leaf — a CID you supply or a literal tag word ("deny"), used
# verbatim — or a compound `[x y …]` meaning `hash(x, y, …)` over its resolved
# children. Resolving an expression walks the tree; every compound node it
# passes through has its preimage published as a self-addressed particle under
# particles/, so a reader can dereference the instruction (bj002 "Reading
# instructions"). This recursion is the homoiconicity bj002 describes made
# executable — an instruction is a tree of the same hashes and CIDs as the
# graph it processes. The whole layer, as expressions:
#
#   confirm            A                          → B
#   deny (edge)        [deny]                      → [A B]
#   deny (cyberlink)   [deny]                      → [A B N]
#   agree / disagree   [agree]                     → B
#   quote              [quote A]                   → B
#   pro / con          [pro C]                     → B
#   question           [question B]                → Q
#   author             [author B]                  → P
#   same               [same P1]                   → P2
#   update             [update [A B]]              → C
#   answer             [answer [[question B] Q]]   → A
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

# Resolve an address expression to a CID. A leaf string is used verbatim (a CID
# input or a tag); a list is hash() over its resolved children, publishing that
# compound's preimage on the way. The one place the grammar is interpreted.
def address [root: path expr: any]: nothing -> string {
    if ($expr | describe) == "string" { return $expr }
    publish $root ...($expr | each {|e| address $root $e })
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
# (bj002 "Confirming an edge").
@example "confirm the edge A → B" { convention confirm QmA… QmB… }
export def confirm [
    cid_from: string # source particle of the edge being confirmed
    cid_to: string # target particle of the edge being confirmed
    --neuron: string
    --claimed-at: string
    --repo: path
    --reassert
]: nothing -> record {
    edge $cid_from $cid_to $neuron $claimed_at $repo $reassert
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
    let target = if $disputed_neuron != null { [$cid_from $cid_to $disputed_neuron] } else { [$cid_from $cid_to] }
    edge ["deny"] $target $neuron $claimed_at $repo $reassert
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
    edge ["update" [$cid_from $cid_to]] $cid_new $neuron $claimed_at $repo $reassert
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
    edge ["quote" $cid_from] $cid_to $neuron $claimed_at $repo $reassert
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
    edge ["agree"] $cid $neuron $claimed_at $repo $reassert
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
    edge ["disagree"] $cid $neuron $claimed_at $repo $reassert
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
    edge ["pro" $target] $argument $neuron $claimed_at $repo $reassert
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
    edge ["con" $target] $argument $neuron $claimed_at $repo $reassert
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
    edge ["question" $about] $question $neuron $claimed_at $repo $reassert
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
    edge ["answer" [["question" $about] $question]] $answer $neuron $claimed_at $repo $reassert
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
    edge ["author" $content] $author_id $neuron $claimed_at $repo $reassert
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
    edge ["same" $name_from] $name_to $neuron $claimed_at $repo $reassert
}
