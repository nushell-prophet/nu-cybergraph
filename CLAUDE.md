# nu-cybergraph

The cybergraph layer over nu-multiproof: link records, birth certificates, portable bundles. The concept is developed in `bostrom-journal` (bj003) — this repo holds the operational spec (README, pinned to code and golden tests) and the thin implementation. Keep concept prose there, mechanics here; don't duplicate.

## Conventions (shared with nu-multiproof)

- `nu-cybergraph/mod.nu` re-exports the non-`_` submodules wholesale; `_*.nu` files are internal, imported by explicit named lists (`use _deps.nu [merkle cid-v0]`). Never `use foo *`.
- Spec-critical byte formats (link record canonicalization, self-addressing) live in `_record.nu` and are pinned by golden tests in `tests/test_record.nu`. Changing them breaks every existing CID — treat as a format version bump, not an edit.
- Prose in git: one paragraph per line, no hard wrapping.

## Dependencies are live sibling checkouts

`_deps.nu` is the single resolution point for nu-multiproof (`../../ai-sandbox-dev-container/nu-multiproof`); toolkit.nu resolves nutest the same way. No pinning — the repos are co-developed. If an interface change in nu-multiproof breaks this repo, fix it here in the same session, or park a note in `todo/`.

## Key invariants

- A certificate in `certs/` is frozen at birth: never regenerate it on later seals — its OTS anchor is the link's earliest provable time bound.
- `verify` must always check against the birth seal (via `seals/<root12>/` snapshots or the bundle's own root), never the repo's current `multiproofs/tree-root.txt`.
- `import` refuses anything that fails merkle structure, signature, record self-addressing, or neuron binding. No partial imports.
- Imported bundles under `imported/` are foreign authority — read-only; re-export means copying them unchanged.

## Running tests

```sh
nu toolkit.nu test          # all tests under tests/
nu toolkit.nu test --fail   # non-zero exit on failure (CI)
```
