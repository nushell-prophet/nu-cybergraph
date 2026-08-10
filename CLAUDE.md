# nu-cybergraph

The cybergraph layer over nu-multiproof: link records, birth certificates, portable bundles. The concept is developed in `bostrom-journal` (bj003) — this repo holds the operational spec (README, pinned to code and golden tests) and the thin implementation. Keep concept prose there, mechanics here; don't duplicate.

All the changes where relevant should be propagated to nu-multiproof.

Pre-1.0: no backwards compatibility to keep. A format change is allowed — it only means every CID is recomputed, and the regeneration script below exists so that costs one run.

## Goal / Done

This repo has one job: make the journal's own cybergraph runnable. **The acceptance test is `bostrom-journal`, branch `nu-cybergraph-regen`** — `nu regenerate-cybergraph.nu` builds the whole graph from `particles/` from nothing, and `dotnu embeds-update cybergraph-from-particles.nu` leaves an empty `git diff`. When both run clean, this repo is done for now. Rehearsal green 2026-07-27 under a throwaway key: 567 links, 567 certificates, all `valid: true`; the editor's own signed run is still pending.

In scope: bj002's encoding half — link record, particle store, convention verbs, `seal`, `verify` — plus the reading commands bj003's first half needs (given a CID, which edges touch it; aggregate over them). Those landed on 2026-07-28 as `link list` / `link touching` / `link tally`; that was the last planned feature.

Parked, not built: `bundle`, `import`, custody receipts, `handoff`. They work and they stay, but they answer no question the acceptance test asks. `handoff` is queued for removal (`todo/20260727-180010-remove-handoff.md`).

A change lands when the acceptance test needs it, or when the exercise hits a defect. "An audit found something better" is not a reason — audit → note → fix → new surface → audit is a loop with no exit, and it is what filled this repo's `todo/`. Parked notes are a record, not a work queue.

## Conventions (shared with nu-multiproof)

- `nu-cybergraph/mod.nu` re-exports the non-`_` submodules wholesale; `_*.nu` files are internal, imported by explicit named lists (`use _record.nu [link-bytes link-cid]`). Never `use foo *`.
- Spec-critical byte formats (link record canonicalization, self-addressing) live in `_record.nu` and are pinned by golden tests in `tests/test_record.nu`. Changing them breaks every existing CID — treat as a format version bump, not an edit.
- Prose in git: one paragraph per line, no hard wrapping.

## Dependencies are live sibling checkouts

`_deps/` is the single resolution point for nu-multiproof (`../nu-multiproof`) — one shim file per dependency, so a `use` site parses only the subtree it needs (nushell re-parses a module at every use site; a single-file facade charged every importer for all six deps). toolkit.nu resolves nutest the same way. No pinning — the repos are co-developed. If an interface change in nu-multiproof breaks this repo, fix it here in the same session, or park a note in `todo/`.

## Key invariants

- A certificate in `certs/` is frozen at birth: never regenerate it on later seals — its OTS anchor is the link's earliest provable time bound.
- `verify` must always check against the birth seal (via `seals/<root12>/` snapshots or the bundle's own root), never the repo's current `multiproofs/tree-root.txt`.
- `import` refuses anything that fails merkle structure, signature, record self-addressing, canonical pubkey form, or signer binding. No partial imports.
- Signer identity is the CID of the pubkey file bytes in canonical form (`<type> <base64>\n`, no comment) — nu-multiproof's `pubkey canonical` is the one definition; `init` writes it, `verify-bundle` enforces it.
- Imported bundles under `imported/` are foreign authority — read-only (no `ots upgrade` inside either); re-export means copying them unchanged plus appending your own custody layer.
- A custody receipt (`receipts/<link>.receipt.json`) is written by `import` outside the read-only copy and frozen by the first seal after — same freeze rule as certificates. Its `prev` hash chains custody layers in order; verification enforces the chain, the `files` byte manifest, and the custodian binding.
- A handoff (`<link>.handoff.json` + detached SSH sig, `bundle --to`) is the ONE directly-signed artifact — it cannot ride a seal because the bundle leaves at export time. Every signature this toolchain makes is under the one `file` namespace (nu-multiproof's `--namespace` was an injection hole and is gone), so domain separation lives in the signed bytes: the handoff's first key is the schema token `cybergraph-handoff-v1`, required byte-exact by `validate-handoff` — the JSON twin of nu-multiproof's `root-statement`. The recipient's receipt hashes it back (`handoff` field), and `import` refuses a bundle handed to a different signer — a fail-fast for honest nodes, not a boundary: an unsealed handoff can be stripped by whoever holds the bytes (accepted residual, see README limits).

## Running tests

```sh
nu toolkit.nu test          # all tests under tests/
nu toolkit.nu test --fail   # non-zero exit on failure (CI)
```
