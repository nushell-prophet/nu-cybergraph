# What sits under the graph home that the layout does not describe.
#
# The reading half of the closed set. SPEC section 3 draws the whole tree a
# graph home may hold, and `_layout.nu strays` turns that drawing into a check;
# this exposes it, so a violation is seen before a seal fails on it.
#
# Named for exactly the set it returns, the same test that named
# `particle uncommitted`: `stray` is already `seal`'s own word for a file it
# refuses to sign. An empty table is the state `seal` requires.

use _repo.nu graph-root
use _layout.nu [ strays ]

# Every path under the graph home the layout does not describe — `path`, the
# directory it sits `under`, and what that directory is `allowed` to hold.
#
# The recovery is always one of two actions, and the `allowed` column says
# which: rename the file to the address it should carry, or move it out of the
# graph home. There is no third option and no flag to seal past it — a seal
# signs whatever is committed under the graph home, so a file the layout cannot
# describe is one the signer would be attesting without having checked it.
export def main [
    --repo: path # Repo root (default: git root of current directory)
]: nothing -> table {
    strays (graph-root $repo)
}
