# nu-cybergraph

The cybergraph layer over nu-multiproof:
link records, birth certificates, portable bundles.
The concept is developed in `bostrom-journal` (bj002 and bj003)
— this repo holds the operational spec (`SPEC.md`, pinned to code and golden tests), the reasons behind it (`README.md`) and the thin implementation.
Keep concept prose there, mechanics here;
don't duplicate.

All the changes where relevant should be propagated to nu-multiproof.

Pre-1.0: no backwards compatibility to keep.
A format change is allowed
— it means every CID is recomputed,
and there is no script for it:
the old artifacts are refused, not migrated.
What it costs, measured on the v1 -> v2 root statement bump:
delete `multiproofs/tree-root.txt` and re-seal,
which restarts the seal chain at `genesis`.
Rewriting the old file in place is not an alternative
— the signature beside it covers exact bytes,
so editing them breaks it.
Certificates frozen under roots stated in the old format stop verifying,
which is why a format change is a decision about the graph,
not an edit.

## An academic prototype, not a product

This is a canonical implementation:
it exists to show the format is right and the reasoning holds,
on a graph small enough to read by hand.
So prefer the plain reading over the clever one
— a walk over a cache, a recomputation over a stored copy —
and never add a mechanism whose only argument is speed.
When graphs outgrow this,
the answer is optimization or a rewrite in a real language,
decided then with the numbers in hand.

Two things this does not license.
It is not permission to undo a cost already measured here
(`link list` at 43s over 567 links, `rg` narrowing at 0.5s against 41s)
— those numbers bought the shape the code has.
And "correct under correct circumstances" is about scale and load, never about input:
refusing malformed, tampered or unprovable bytes loudly is the product,
so a check is never what gets dropped for simplicity.

## Conventions (shared with nu-multiproof)

- `nu-cybergraph/mod.nu` re-exports the non-`_` submodules wholesale;
  `_*.nu` files are internal, imported by explicit named lists (`use _record.nu [link-bytes link-cid]`).
  Never `use foo *`.
- Spec-critical byte formats (link record canonicalization, self-addressing) live in `_record.nu`
  and are pinned by golden tests in `tests/test_record.nu`.
  Changing them breaks every existing CID
  — treat as a format version bump, not an edit.

## Dependencies are live sibling checkouts

`_deps/` is the single resolution point for nu-multiproof (`../nu-multiproof`)
— one shim file per dependency,
so a `use` site parses only the subtree it needs (nushell re-parses a module at every use site; a single-file facade charged every importer for all six deps).
toolkit.nu resolves nutest the same way.
No pinning
— the repos are co-developed.
If an interface change in nu-multiproof breaks this repo,
fix it here in the same session,
or park a note in `todo/`.

## Key invariants

- The seal chain is contiguous:
  every root statement carries `seq` (from 0, `prev` = the root it supersedes, `genesis` only at 0),
  and `seal chain` refuses a gap
  — a missing `seals/<root12>/` snapshot is certificates that verify against nothing,
  not a shorter list.
- The graph home is a closed set:
  SPEC section 3's tree is the whole of what may sit under it,
  and `_layout.nu strays` is that drawing as a check.
  `seal` refuses on the whole set with no override
  — it stages those directories wholesale, so an undescribed file would be signed unchecked —
  while every reading refuses on the top level alone, through `graph-root`,
  because a reader that cannot tell a foreign layout from an empty one answers `[]` and is believed.
  The rule recognises `multiproofs/` without policing it,
  and stops at a bundle's edge under `exports/` and `imported/`.
- The store is committed before the seal, not after:
  the manifest is every git-tracked file under the graph home,
  so a `particles/` file outside the index enters no root
  while the link naming it is signed and frozen.
  `seal` refuses while the graph reaches an untracked store file (`--allow-untracked-particles` seals without those bytes, but never past a name under `particles/` that is no address);
  `particle uncommitted` is the reading,
  `--propose-commit` writes the commit.
- A certificate in `certs/` is frozen at birth:
  never regenerate it on later seals
  — its OTS anchor is the link's earliest provable time bound.
- `verify` must always check against the birth seal (via `seals/<root12>/` snapshots or the bundle's own root),
  never the repo's current `multiproofs/tree-root.txt`.
- `import` refuses anything that fails merkle structure, signature, record self-addressing, canonical pubkey form, or signer binding.
  No partial imports.
- Signer identity is the CID of the pubkey file bytes in canonical form (`<type> <base64>\n`, no comment)
  — nu-multiproof's `pubkey canonical` is the one definition;
  `init` writes it, `verify-bundle` enforces it.
- Imported bundles under `imported/` are foreign authority
  — read-only (no `ots upgrade` inside either);
  re-export means copying them unchanged plus appending your own custody layer.
- A custody receipt (`receipts/<author>/<edge>.receipt.json`
  — paths mirror the link layout,
  and the receipt states the act's components, `cid_from`/`cid_to`/`signer`, rather than its derived CID,
  so it reads standalone — same as the handoff)
  is written by `import` outside the read-only copy
  and frozen by the first seal after
  — same freeze rule as certificates.
  Its `prev` hash chains custody layers in order;
  verification enforces the chain, the `files` byte manifest, and the custodian binding.
- A handoff (`<edge>.handoff.json` + detached SSH sig, `bundle --to`) is the ONE directly-signed artifact
  — it cannot ride a seal
  because the bundle leaves at export time.
  Every signature this toolchain makes is under the one `file` namespace (nu-multiproof's `--namespace` was an injection hole and is gone),
  so domain separation lives in the signed bytes:
  the handoff's first key is the schema token `cybergraph-handoff-v2`,
  required byte-exact by `validate-handoff`
  — the JSON twin of nu-multiproof's `root-statement`.
  Like a receipt, it states the act's components (`cid_from`/`cid_to`/`signer`) rather than its derived CID;
  v1 was the version that carried the CID.
  The recipient's receipt hashes it back (`handoff` field),
  and `import` refuses a bundle handed to a different signer
  — a fail-fast for honest nodes, not a boundary:
  an unsealed handoff can be stripped by whoever holds the bytes (accepted residual, see README limits).

## Running tests

```sh
nu toolkit.nu test          # all tests under tests/
nu toolkit.nu test --fail   # non-zero exit on failure (CI)
```
