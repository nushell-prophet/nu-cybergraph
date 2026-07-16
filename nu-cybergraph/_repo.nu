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
