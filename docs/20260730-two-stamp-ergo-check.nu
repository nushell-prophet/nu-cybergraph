# nu-multiproof @ two-stamp-ergo, checked against nu-cybergraph
#
# The question: does the upstream branch break us, and does it give us anything?
# Answer, in one line each — it does not break us, it gives us a dated
# endorsement for free, and it carries one real defect that bites operator
# scripts.
#
# This file is a dotnu embeds document: every `| print $in` line below is
# executed and its real output written underneath as `# =>` comments. Refresh
# with `dotnu embeds-update docs/20260730-two-stamp-ergo-check.nu`, then read
# the git diff. An empty diff means every claim here still holds.
#
# Everything executable here is OFFLINE. The one claim that needs a live
# OpenTimestamps calendar was run once, by hand, and its result pinned to
# `docs/two-stamp-ergo-evidence.nuon`, which section 3 reads. A real stamp is a
# permanent public write, so it must not sit in a path that re-runs on every
# refresh.

use /Users/user/git/cy-container/nu-cybergraph/nu-cybergraph
use /Users/user/git/cy-container/nu-cybergraph/nu-cybergraph/_verify-helpers.nu [verify-bundle]
use /Users/user/git/cy-container/nu-cybergraph/nu-cybergraph/_signer.nu [own-signer]

const MP = "/Users/user/git/ai-sandbox-dev-container/nu-multiproof"
const CG = "/Users/user/git/cy-container/nu-cybergraph"

# ─────────────────────────────────────────────────────────────────────────────
# 1. What we are testing against
#
# The branch is 26 commits of seal/merkle/ots work. Only five files under
# nu-multiproof/ changed; the four modules we import that are NOT in this list —
# cid-v0, pubkey, init, ssh-sign — are byte-identical to main.

^git -C $MP diff --stat main...two-stamp-ergo -- nu-multiproof/ | print $in
# =>  nu-multiproof/_fs.nu     |  12 ++-
# =>  nu-multiproof/_stamps.nu |  94 +++++++++++++++++++++++
# =>  nu-multiproof/merkle.nu  |  73 ++++++++++--------
# =>  nu-multiproof/ots.nu     | 139 +++++++++++++++++++++++++++++++---
# =>  nu-multiproof/seal.nu    | 190 +++++++++++++++++++++++++++++++++++++++++++++--
# =>  5 files changed, 462 insertions(+), 46 deletions(-)

# ─────────────────────────────────────────────────────────────────────────────
# 2. The one real defect: a parse-time collision, new on this branch
#
# Upstream's new `seal status` carries an @example whose body calls `seal
# status`. Nushell parses an example body against whatever `seal` is in scope.
# Import a file-shim `seal.nu` first — which is exactly what `_deps/` does — and
# the module fails to parse. nu-cybergraph's `seal` takes no positional, so
# `status` reads as an extra argument.

let tmp = mktemp --directory

$"use ($CG)/nu-cybergraph/seal.nu
use ($MP)/nu-multiproof
print ok" | save --force ($tmp | path join collide.nu)

# Only the diagnostic and the flagged text are shown: the rest of the error is
# absolute paths, which would churn the diff on every refresh.
do { ^nu ($tmp | path join collide.nu) } | complete
| $"exit ($in.exit_code): ($in.stderr | lines | where {|l| ($l | str contains 'nu::parser') or ($l | str contains 'seal status') } | str trim | str join ' | ')"
| print $in
# => exit 1: Error: nu::parser::extra_positional | 274 |     seal status

# Reverse the two imports and it parses clean — which is why the test suite and
# the acceptance test never see it. `_deps/` shims import single files, and
# `regenerate-cybergraph.nu` imports the module under a prefix.
$"use ($MP)/nu-multiproof
use ($CG)/nu-cybergraph/seal.nu
print 'parses clean with the imports reversed'" | save --force ($tmp | path join ok.nu)

do { ^nu ($tmp | path join ok.nu) } | complete | get stdout | str trim | print $in
# => parses clean with the imports reversed

# Verified once, by hand, not embedded because it needs a second checkout:
#   git -C $MP archive main | tar -x -C /tmp/mpmain
# and the same colliding import pair parses clean against main. So this is new
# on the branch, and it belongs upstream — the example should call `main status`
# rather than name the module's own command.

# ─────────────────────────────────────────────────────────────────────────────
# 3. What the branch gives us: a dated endorsement, with no code change here
#
# Before, an SSH signature carried no time. A `.sig` made today fitted a
# year-old bundle and nothing on disk contradicted it. A portable bundle could
# prove "this record existed by block N" but not "the signer endorsed it by
# block N" — the claim that has to survive a key compromise.
#
# Upstream now stamps the root statement AND every signature over it, both
# `--into` one bundle directory. Nothing in nu-cybergraph had to change:
# `seal.nu:68` calls upstream `seal` opaquely, `bundle.nu:64-77` copies the
# whole OTS directory rather than a file list, and `_verify-helpers.nu:60`
# passes the `merkle verify` record through with `insert`/`update` only — it
# never projects a fixed column set, so a new upstream field survives.
#
#   ran once, NETWORK, two calendar posts:
#     nu-cybergraph init  ->  link add  ->  seal  ->  bundle  ->  verify-bundle
#   its result is pinned here, and this line only reads it back:

open ($CG | path join docs two-stamp-ergo-evidence.nuon) | print $in
# => ╭──────────────────────────────────────┬───────────────────────────────────────╮
# => │                                      │ ╭───┬─────────────╮                   │
# => │ seal_result_keys                     │ │ 0 │ manifest    │                   │
# => │                                      │ │ 1 │ root_cid    │                   │
# => │                                      │ │ 2 │ merkle_root │                   │
# => │                                      │ │ 3 │ root_sig    │                   │
# => │                                      │ │ 4 │ root_ots    │                   │
# => │                                      │ │ 5 │ sig_ots     │                   │
# => │                                      │ ╰───┴─────────────╯                   │
# => │ root_ots                             │ tree-root.ots                         │
# => │                                      │ ╭───┬───────────────────────────────╮ │
# => │ sig_ots                              │ │ 0 │ tree-root.txt.a9c18f81fe273b8 │ │
# => │                                      │ │   │ fd60e16f33447cd3b841511fef43c │ │
# => │                                      │ │   │ b18dfe9c0e3931fa9860.ots      │ │
# => │                                      │ ╰───┴───────────────────────────────╯ │
# => │                                      │ ╭───┬───────────────────────────────╮ │
# => │ ots_bundle_contents                  │ │ 0 │ tree-root.ots                 │ │
# => │                                      │ │ 1 │ tree-root.txt                 │ │
# => │                                      │ │ 2 │ tree-root.txt.a9c18f81fe273b8 │ │
# => │                                      │ │   │ fd60e16f33447cd3b841511fef43c │ │
# => │                                      │ │   │ b18dfe9c0e3931fa9860.ots      │ │
# => │                                      │ │ 3 │ tree-root.txt.a9c18f81fe273b8 │ │
# => │                                      │ │   │ fd60e16f33447cd3b841511fef43c │ │
# => │                                      │ │   │ b18dfe9c0e3931fa9860.sig      │ │
# => │                                      │ ╰───┴───────────────────────────────╯ │
# => │                                      │ ╭────┬──────────────────╮             │
# => │ verify_columns                       │ │  0 │ valid            │             │
# => │                                      │ │  1 │ structure_valid  │             │
# => │                                      │ │  2 │ root             │             │
# => │                                      │ │  3 │ manifest_root    │             │
# => │                                      │ │  4 │ leaf             │             │
# => │                                      │ │  5 │ content_verified │             │
# => │                                      │ │  6 │ signatures       │             │
# => │                                      │ │  7 │ ots              │             │
# => │                                      │ │  8 │ endorsements     │             │
# => │                                      │ │  9 │ error            │             │
# => │                                      │ │ 10 │ record           │             │
# => │                                      │ │ 11 │ signer           │             │
# => │                                      │ │ 12 │ handoff          │             │
# => │                                      │ │ 13 │ custody          │             │
# => │                                      │ │ 14 │ handed_to        │             │
# => │                                      │ ╰────┴──────────────────╯             │
# => │ valid                                │ true                                  │
# => │ content_anchor                       │ pending                               │
# => │                                      │ ╭───┬─────────╮                       │
# => │ endorsement_anchor                   │ │ 0 │ pending │                       │
# => │                                      │ ╰───┴─────────╯                       │
# => │ endorsement_signer_is_the_key        │ true                                  │
# => │ endorsement_anchor_inside_the_bundle │ true                                  │
# => │                                      │ ╭───┬───────────────────────────────╮ │
# => │ exported_bundle_ots_dir              │ │ 0 │ tree-root.ots                 │ │
# => │                                      │ │ 1 │ tree-root.txt                 │ │
# => │                                      │ │ 2 │ tree-root.txt.a9c18f81fe273b8 │ │
# => │                                      │ │   │ fd60e16f33447cd3b841511fef43c │ │
# => │                                      │ │   │ b18dfe9c0e3931fa9860.ots      │ │
# => │                                      │ │ 3 │ tree-root.txt.a9c18f81fe273b8 │ │
# => │                                      │ │   │ fd60e16f33447cd3b841511fef43c │ │
# => │                                      │ │   │ b18dfe9c0e3931fa9860.sig      │ │
# => │                                      │ ╰───┴───────────────────────────────╯ │
# => ╰──────────────────────────────────────┴───────────────────────────────────────╯

# `pending` is the success case on a fresh seal: the digest reached the
# calendar, and Bitcoin confirmation — which turns it into `anchored <height>` —
# takes hours.

# ─────────────────────────────────────────────────────────────────────────────
# 4. The offline surface still works, end to end
#
# Two throwaway signers, sha256 git backend, ed25519 keys, every seal
# --no-stamp. Only values that do not change between runs are printed: a signer
# CID is derived from a freshly generated key, so CIDs and fingerprints would
# churn the diff on every refresh.

def make-signer [tmp: path name: string]: nothing -> record {
    let repo = $tmp | path join $name
    mkdir $repo
    ^git init --object-format=sha256 -q $repo
    ^git -C $repo config user.name $name
    ^git -C $repo config user.email $"($name)@test"
    let key = $tmp | path join $"key-($name)"
    ^ssh-keygen -t ed25519 -f $key -N "" -C $name -q
    ^git -C $repo config user.signingKey $key
    nu-cybergraph init --repo $repo | ignore
    {repo: $repo home: ($repo | path join cybergraph) key: $key}
}

let a = make-signer $tmp "a"
let b = make-signer $tmp "b"

let A = nu-cybergraph particle add "doc A: the original" --repo $a.repo
let B = nu-cybergraph particle add "doc B: the excerpt" --repo $a.repo
let P = nu-cybergraph particle add "person P" --repo $a.repo

# A spread of convention verbs, so the reading commands have a real graph.
nu-cybergraph convention quote $A $B --repo $a.repo | ignore
nu-cybergraph convention agree $B --repo $a.repo | ignore
nu-cybergraph convention author $B $P --repo $a.repo | ignore
nu-cybergraph convention question $B "what is it?" --repo $a.repo | ignore
nu-cybergraph convention translation $A "перевод" --repo $a.repo | ignore
let plain = nu-cybergraph link add $A $B --repo $a.repo

# Reading the graph back: which edges touch B, and what they add up to.
nu-cybergraph link touching $B --repo $a.repo | select role op | sort-by role op | print $in
# => ╭───┬────────────────┬──────────╮
# => │ # │      role      │    op    │
# => ├───┼────────────────┼──────────┤
# => │ 0 │ cid_from.about │ author   │
# => │ 1 │ cid_from.about │ question │
# => │ 2 │ cid_to         │ agree    │
# => │ 3 │ cid_to         │ quote    │
# => │ 4 │ cid_to         │          │
# => ╰───┴────────────────┴──────────╯

# The rg-narrowed walk and the full scan must agree — a disagreement here is the
# bug the `--scan` flag exists to catch.
let narrowed = nu-cybergraph link touching $B --repo $a.repo | to nuon
let scanned = nu-cybergraph link touching $B --repo $a.repo --scan | to nuon
$"touching --scan agrees with the indexed walk: ($narrowed == $scanned)" | print $in
# => touching --scan agrees with the indexed walk: true

nu-cybergraph link tally $B --repo $a.repo | select op role signers | sort-by op role | print $in
# => ╭───┬──────────┬────────────────┬─────────╮
# => │ # │    op    │      role      │ signers │
# => ├───┼──────────┼────────────────┼─────────┤
# => │ 0 │ agree    │ cid_to         │       1 │
# => │ 1 │ author   │ cid_from.about │       1 │
# => │ 2 │ question │ cid_from.about │       1 │
# => │ 3 │ quote    │ cid_to         │       1 │
# => │ 4 │          │ cid_to         │       1 │
# => ╰───┴──────────┴────────────────┴─────────╯

# Seal: certificates freeze at birth, and the root statement is snapshotted.
let sealed = nu-cybergraph seal --repo $a.repo --no-stamp
$"newborn certificates: ($sealed.newborn), links on disk: (nu-cybergraph link list --repo $a.repo | length)" | print $in
# => newborn certificates: 6, links on disk: 6

# Verify goes through the portable bundle a stranger would get, never through
# this repo's current tree-root.txt.
let v = nu-cybergraph verify $plain.cid --repo $a.repo | first
{valid: $v.valid, signer_bound: $v.signer.bound, ots: $v.ots.status, endorsements: ($v.endorsements | length)} | print $in
# => ╭──────────────┬────────╮
# => │ valid        │ true   │
# => │ signer_bound │ true   │
# => │ ots          │ absent │
# => │ endorsements │ 1      │
# => ╰──────────────┴────────╯

# Unstamped, the row is still there: one endorsement per validly-signing key,
# with an `absent` anchor. So the signature is always named; only its date is
# missing without a stamp. `_verify-helpers.nu:244-249` then inserts five more
# columns — `record`, `signer`, `handoff`, `custody`, `handed_to` — and an
# `insert` throws on a name that already exists. `endorsements` clashes with
# none of them, which is the whole reason this branch does not break verify.
$v | columns | print $in
# => ╭────┬──────────────────╮
# => │  0 │ valid            │
# => │  1 │ structure_valid  │
# => │  2 │ root             │
# => │  3 │ manifest_root    │
# => │  4 │ leaf             │
# => │  5 │ content_verified │
# => │  6 │ signatures       │
# => │  7 │ ots              │
# => │  8 │ endorsements     │
# => │  9 │ error            │
# => │ 10 │ record           │
# => │ 11 │ signer           │
# => │ 12 │ handoff          │
# => │ 13 │ custody          │
# => │ 14 │ handed_to        │
# => ╰────┴──────────────────╯

# Handoff, import, custody: A hands the link to B, B imports it, seals to freeze
# the custody receipt, and verifies it by CID alone. `custody_layers` is 0 at
# the first hop — a layer records a PREVIOUS custodian, and B received this
# straight from its author. B re-exporting to C is what makes the first layer.
let B_ID = own-signer $b.home
let h1 = nu-cybergraph bundle $plain.cid --repo $a.repo --to $B_ID --key $a.key --out ($tmp | path join h1)
nu-cybergraph import $h1 --repo $b.repo | ignore
nu-cybergraph seal --repo $b.repo --no-stamp | ignore
let vb = nu-cybergraph verify $plain.cid --repo $b.repo | first
{valid: $vb.valid, custody_layers: ($vb.custody | length), custody_all_valid: ($vb.custody | all {|c| $c.valid }), handed_to_is_b: ($vb.handed_to == $B_ID)} | print $in
# => ╭───────────────────┬──────╮
# => │ valid             │ true │
# => │ custody_layers    │ 0    │
# => │ custody_all_valid │ true │
# => │ handed_to_is_b    │ true │
# => ╰───────────────────┴──────╯

# The signer fingerprint that `bundle.nu:47` recovers by parsing a filename —
# `^tree-root\.txt\.(?<fp>.+)\.sig$` — still matches what a real seal writes.
ls ($h1 | path join multiproofs) | get name | path basename
| where {|f| $f | str ends-with ".sig" }
| each {|f| $f | parse --regex '^tree-root\.txt\.(?<fp>.+)\.sig$' | get fp?.0? | is-not-empty }
| $"every snapshot signature name parses into a fingerprint: ($in | all {|x| $x })"
| print $in
# => every snapshot signature name parses into a fingerprint: true

rm --recursive --force $tmp

# ─────────────────────────────────────────────────────────────────────────────
# 5. What was checked and did not happen
#
# A suspected defect, refuted: `seal.nu:95` freezes seals/<root12>/ only once,
# while upstream `ots stamp` re-copies the signature on every run. With a
# randomized key (plain ecdsa, and the editor's ecdsa-sk) a re-seal would then
# leave the snapshot holding a signature no anchor covers. It does not happen —
# every seal produces a NEW merkle root, because `seal.nu:61` stages seals/ into
# the manifest, so seal N+1 catalogues seal N's snapshot. Four seals with no new
# links gave four distinct roots. And in a patched copy where two seals DO share
# a root, the endorsement is still found: `ots stamp` archives a superseded
# proof instead of overwriting it, and `merkle verify` matches stamps by content
# commitment, not by filename.
#
# Left as a note, not a change: todo/20260730-152000-seal-snapshot-guard-silently-coupled.md
#
# Not built on top of this: nothing here ACTS on an endorsement. `bound` and
# `check-handoff` still read `signatures`. Making `import` refuse an undated
# endorsement would be a real code change, and the acceptance test does not ask
# for one.
