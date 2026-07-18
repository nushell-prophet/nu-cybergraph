# Single resolution point for nu-multiproof (live sibling checkout, not a pin —
# the repos are co-developed): edit these paths when the checkout lives elsewhere.
# One dependency per file so a `use` site parses only the subtree it needs:
# nushell re-parses a module at every use site, so the old single-file facade
# charged every importer for all six dependencies.
export use ../../../../ai-sandbox-dev-container/nu-multiproof/nu-multiproof/merkle.nu
