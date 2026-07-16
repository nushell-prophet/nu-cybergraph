# Resolve a target repo root — same semantics as nu-multiproof's internal
# _repo.nu, duplicated (8 lines) rather than imported: cross-repo imports of
# another project's _-internals carry no compatibility promise. An explicit
# path is taken as-is (no git check) — verify runs against plain bundle
# directories, same contract as nu-multiproof's `merkle verify --repo`.
export def repo-root [repo?: path]: nothing -> path {
    if $repo != null {
        return ($repo | path expand)
    }
    let result = ^git rev-parse --show-toplevel | complete
    if $result.exit_code != 0 {
        error make {msg: "not inside a git repository — pass --repo to target one explicitly"}
    }
    $result.stdout | str trim
}

# The graph home inside a repo: <root>/cybergraph when that directory exists,
# the root itself otherwise. A repo of arbitrary shape keeps its whole graph
# (links/ certs/ seals/ multiproofs/ exports/ imported/) in one subdirectory —
# `init --nested` opts in, nothing else changes. Particles are referenced by
# CID, not path, so they never need to live under the graph home (or in the
# repo at all); the seal manifest then covers only the graph subtree.
export def graph-root [repo?: path]: nothing -> path {
    let root = repo-root $repo
    let nested = $root | path join cybergraph
    if ($nested | path exists) { $nested } else { $root }
}
