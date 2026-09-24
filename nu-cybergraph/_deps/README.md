# `_deps/` — the single resolution point for nu-multiproof

One shim file per dependency, each a bare `export use` of `nu-multiproof/` inside this repo.
Nothing else in the repo names that path.

A pin by construction
— a clone of this repo carries the exact nu-multiproof it was tested with.
nu-multiproof is still co-developed and published on its own,
exported from this same directory.
An interface change in it that breaks this repo is fixed here in the same session,
or parked in `todo/`.

One file per dependency, not one facade:
nushell re-parses a module at every `use` site,
so a single-file facade charged every importer for all six dependencies.
A `use _deps/cid-v0.nu` parses only the subtree it needs.
