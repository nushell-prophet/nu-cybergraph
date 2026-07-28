# `_deps/` — the single resolution point for nu-multiproof

One shim file per dependency, each a bare `export use` of a live sibling checkout. Edit these paths when the checkout lives elsewhere; nothing else in the repo names them.

Not a pin — the two repos are co-developed, so `_deps/` follows whatever is on disk. An interface change upstream that breaks this repo is fixed here in the same session, or parked in `todo/`.

One file per dependency, not one facade: nushell re-parses a module at every `use` site, so a single-file facade charged every importer for all six dependencies. A `use _deps/cid-v0.nu` parses only the subtree it needs.
