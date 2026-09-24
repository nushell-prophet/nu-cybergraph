# nu-multiproof @ two-stamp-ergo, checked against nu-cybergraph
#
# The question: does the upstream branch break us, and does it give us anything?
# Answer, in one line each — it does not break us, it gives us a dated
# endorsement for free, and it carries one real defect that bites operator
# scripts.
#
# SUPERSEDED IN PART, and kept running rather than frozen. This was the check
# that let the two-stamp branch in; what it recommended was then taken further
# than it proposed. Section 5 says nothing here acts on an endorsement — that is
# no longer true, `verify` now reports `signer.endorsed` and `import` returns it.
# And the two anchors this file weighs are now one: `seal` passes
# --no-content-anchor on every run, so the root statement is deliberately left
# undated and upstream's `ots` field is dropped from the verify record. The
# reasoning for that is in the branch's commit bodies, not here. What stays true
# is everything this file EXECUTES, which is why it is still refreshed instead of
# being marked historical — the section-3 evidence pinned in
# `two-stamp-ergo-evidence.nuon` is a record of a live run on 2026-07-30 and
# describes the layout of that day, not of today.
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

# Relative to this file, never absolute: an absolute path names one machine's
# checkout, so a refresh would check whatever code sits there rather than the
# code beside this file, which is the one thing an embeds document exists to
# prevent.
use ../nu-cybergraph
use ../nu-cybergraph/_verify-helpers.nu [ verify-bundle ]
use ../nu-cybergraph/_signer.nu [ own-signer ]

# Sections 2 and 3 need those two as ABSOLUTE paths at runtime: section 2 writes
# a script into a temp dir, which has no relative path back here. Resolved from
# the working directory rather than with `path self`, because `dotnu` evaluates
# this file as a string — `path self` raises "Couldn't find current file" there,
# and the refresh command in the header is the contract this has to satisfy.
# dotnu cds into the script's own directory first, so `..` is this repo; running
# the file by hand means `cd docs` first.
let CG = ".." | path expand
let MP = "../nu-multiproof" | path expand

# ─────────────────────────────────────────────────────────────────────────────
# 1. What we are testing against
#
# The branch was 26 commits of seal/merkle/ots work, and when this was first run
# it touched five files under nu-multiproof/, none of them cid-v0, pubkey, init
# or ssh-sign — so the four modules we import were byte-identical to main.
#
# The count had since grown to ten, and those four were then in it. That was
# not the branch changing: `main` moved on under it, through a topiary pass and a
# return-type sweep (nu-multiproof 95e69f9), so a three-dot diff reported work
# that landed after this check rather than work this branch proposed. The point
# the line was making is spent — it is kept because it dates the comparison.
#
# STOPPED EXECUTING, and that is worth naming rather than quietly deleting.
# The line was `git diff --stat main...two-stamp-ergo`, and `main` is what went:
# the trunk of the checkout it ran against is `master`. The branch itself is
# still there (`git -C nu-multiproof branch` lists both `two-stamp` and
# `two-stamp-ergo`), and `master...two-stamp-ergo` runs today — it reports 23
# files, which is the point the paragraph above already made about a three-dot
# diff against a trunk that moved. An external command exiting non-zero raises,
# and this one stood at the top of the file, so nothing below it ran either and
# the header's claim to be refreshed rather than frozen was false for the whole
# document. Frozen as the comment below: a spent comparison needs its date, not
# a rerun against a trunk that is no longer the one it was measured from.
#
#   nu-multiproof/_fs.nu         |  12 ++-
#   nu-multiproof/_stamps.nu     |  94 +++++++++++++++++++++
#   nu-multiproof/cid-v0.nu      |   4 +-
#   nu-multiproof/init.nu        |   2 +-
#   nu-multiproof/merkle.nu      |  87 +++++++++++--------
#   nu-multiproof/ots.nu         | 147 +++++++++++++++++++++++++++++---
#   nu-multiproof/pubkey.nu      |   2 +-
#   nu-multiproof/seal.nu        | 194 +++++++++++++++++++++++++++++++++++++++++--
#   nu-multiproof/ssh-sign.nu    |   4 +-
#   nu-multiproof/tree-hashes.nu |   4 +-
#   10 files changed, 484 insertions(+), 66 deletions(-)

# ─────────────────────────────────────────────────────────────────────────────
# 2. The one real defect: a parse-time collision — REPORTED, AND FIXED UPSTREAM
#
# Upstream's new `seal status` carried an @example whose body called `seal
# status`. Nushell parses an example body against whatever `seal` is in scope.
# Import a file-shim `seal.nu` first — which is exactly what `_deps/` does — and
# the module failed to parse. nu-cybergraph's `seal` takes no positional, so
# `status` read as an extra argument.
#
# The probe below now prints `exit 0` and an empty diagnostic, which is the fix
# landing: nu-multiproof a38415e made every @example body call its command the
# way a user types it — `nu-multiproof seal status`, not a bare `seal status`.
# The probe is kept rather than deleted, because it is now the regression test
# for that fix and it costs one subprocess.

let tmp = mktemp --directory

$"use ($CG)/nu-cybergraph/seal.nu
use ($MP)/nu-multiproof
print ok" | save --force ($tmp | path join collide.nu)

# Only the diagnostic and the flagged text are shown: the rest of the error is
# absolute paths, which would churn the diff on every refresh.
do { ^nu ($tmp | path join collide.nu) } | complete
| $"exit ($in.exit_code): ($in.stderr | lines | where (($it | str contains 'nu::parser') or ($it | str contains 'seal status')) | str trim | str join ' | ')"
| print $in
# => exit 0: 

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
# — `main` as it stood on 2026-07-30; that name is gone now, same as in section
# 1, and the trunk to archive today is `master`. So this is new
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
nu-cybergraph convention quote-particle $A $B --repo $a.repo | ignore
nu-cybergraph convention agree-particle $B --repo $a.repo | ignore
nu-cybergraph convention author-particle $B $P --repo $a.repo | ignore
nu-cybergraph convention question $B "what is it?" --repo $a.repo | ignore
nu-cybergraph convention translation-particle $A "перевод" --repo $a.repo | ignore
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
let v = nu-cybergraph verify $plain.edge_cid --repo $a.repo | first
{valid: $v.valid signer_bound: $v.signer.bound endorsed: $v.signer.endorsed.status endorsements: ($v.endorsements | length)} | print $in
# => ╭──────────────┬────────╮
# => │ valid        │ true   │
# => │ signer_bound │ true   │
# => │ endorsed     │ absent │
# => │ endorsements │ 1      │
# => ╰──────────────┴────────╯

# Unstamped, the row is still there: one endorsement per validly-signing key,
# with an `absent` anchor. So the signature is always named; only its date is
# missing without a stamp. `_verify-helpers.nu`'s `UNREAD_COLUMNS` then adds five
# more — `record`, `signer`, `handoff`, `custody`, `handed_to` — by `insert`, which
# throws on a name upstream already returned. `endorsements` collides with none of
# them, which is the whole reason this branch does not break verify. (Named, not
# cited by line: the line numbers this file used to give rot on the next edit, and
# one just did.)
$v | columns | print $in
# => ╭────┬─────────────────────╮
# => │  0 │ valid               │
# => │  1 │ structure_valid     │
# => │  2 │ root                │
# => │  3 │ manifest_root       │
# => │  4 │ leaf                │
# => │  5 │ content_verified    │
# => │  6 │ content_enumeration │
# => │  7 │ signatures          │
# => │  8 │ endorsements        │
# => │  9 │ error               │
# => │ 10 │ record              │
# => │ 11 │ signer              │
# => │ 12 │ handoff             │
# => │ 13 │ custody             │
# => │ 14 │ handed_to           │
# => ╰────┴─────────────────────╯

# Handoff, import, custody: A hands the link to B, B imports it, seals to freeze
# the custody receipt, and verifies it by CID alone. `custody_layers` is 0 at
# the first hop — a layer records a PREVIOUS custodian, and B received this
# straight from its author. B re-exporting to C is what makes the first layer.
let B_ID = own-signer $b.home
let h1 = nu-cybergraph bundle $plain.edge_cid --repo $a.repo --to $B_ID --key $a.key --out ($tmp | path join h1)
nu-cybergraph import $h1 --repo $b.repo | ignore
nu-cybergraph seal --repo $b.repo --no-stamp | ignore
let vb = nu-cybergraph verify $plain.edge_cid --repo $b.repo | first
{valid: $vb.valid custody_layers: ($vb.custody | length) custody_all_valid: ($vb.custody | all {|c| $c.valid }) handed_to_is_b: ($vb.handed_to == $B_ID)} | print $in
# => ╭───────────────────┬──────╮
# => │ valid             │ true │
# => │ custody_layers    │ 0    │
# => │ custody_all_valid │ true │
# => │ handed_to_is_b    │ true │
# => ╰───────────────────┴──────╯

# The signer fingerprint that `bundle.nu:47` recovers by parsing a filename —
# `^tree-root\.txt\.(?<fp>.+)\.sig$` — still matches what a real seal writes.
ls ($h1 | path join multiproofs) | get name | path basename
| where ($it | str ends-with ".sig")
| all { parse --regex '^tree-root\.txt\.(?<fp>.+)\.sig$' | get --optional 0.fp | is-not-empty }
| $"every snapshot signature name parses into a fingerprint: ($in)"
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
#
# OUTDATED, kept as the record of what was decided on 2026-07-30. Reading the
# endorsement is exactly what happened next: `verify` returns `signer.endorsed`,
# each custody layer carries its custodian's, and `import` reports it. Still true
# is the last sentence — nothing ENFORCES it. `bound` and `check-handoff` read
# `signatures`, no anchor is a condition of `valid`, and whether `import` should
# refuse an undated endorsement remains open, for the reason given here: a fresh
# stamp reads `pending` for hours and the acceptance test does not ask.
