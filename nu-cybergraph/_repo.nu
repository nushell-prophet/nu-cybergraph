# Resolve a target repo root — same semantics as nu-multiproof's internal
# _repo.nu, duplicated (8 lines) rather than imported: cross-repo imports of
# another project's _-internals carry no compatibility promise. An explicit
# path must exist but needn't be a git repo — verify runs against plain bundle
# directories, same contract as nu-multiproof's `merkle verify --repo`.
export def repo-root [repo?: path]: nothing -> path {
    if $repo != null {
        let expanded = $repo | path expand
        # Catch the typo here: unchecked, it surfaces later as a confusing
        # downstream error ("no pubkey registered" for a path that isn't there).
        if not ($expanded | path exists) {
            error make {msg: $"repo path does not exist: ($expanded)"}
        }
        return $expanded
    }
    let result = ^git rev-parse --show-toplevel | complete
    if $result.exit_code != 0 {
        error make {msg: "not inside a git repository — pass --repo to target one explicitly"}
    }
    $result.stdout | str trim
}

# The graph home inside a repo: always <root>/cybergraph. One rule, no
# root-layout fallback — the author recreated the only such graph rather
# than carry a second layout forever. Whole-repo attestation (what root
# layout used to give the tool repo) is plain nu-multiproof's job, not the
# graph's. Files are referenced by CID, not path, so they never need to
# live under the graph home (or in the repo at all); the seal manifest
# covers only the graph subtree.
export def graph-root [repo?: path]: nothing -> path {
    repo-root $repo | path join cybergraph
}
