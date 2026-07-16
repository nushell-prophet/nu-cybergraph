# Single resolution point for the nu-multiproof dependency. Internal module:
# mod.nu does not re-export _*.nu files; impl files import the names they
# need explicitly (`use _deps.nu [merkle cid-v0]`).
#
# Why a live sibling checkout and not a submodule: the two repos are
# co-developed on this machine (same convention as nutest for tests), and a
# pinned copy would lag behind fixes landed minutes earlier. This is the ONE
# place to edit when the checkout lives elsewhere.
export use ../../../ai-sandbox-dev-container/nu-multiproof/nu-multiproof/cid-v0.nu
export use ../../../ai-sandbox-dev-container/nu-multiproof/nu-multiproof/merkle.nu
export use ../../../ai-sandbox-dev-container/nu-multiproof/nu-multiproof/seal.nu
export use ../../../ai-sandbox-dev-container/nu-multiproof/nu-multiproof/init.nu
