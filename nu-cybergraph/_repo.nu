# Resolve a target repo root — the same rule as nu-multiproof's internal
# _repo.nu with cybergraph/ as the marker, duplicated rather than imported:
# cross-repo imports of another project's _-internals carry no compatibility
# promise. An explicit path must exist but needn't be a git repo — verify runs
# against plain bundle directories, same contract as nu-multiproof's
# `merkle verify --repo`.
use _layout.nu [ assert-known-home ]

# The given repo path expanded, or — when null — the nearest directory from the
# current one up to the git root that holds cybergraph/; with none, the git
# root itself. Under --init, the current directory.
export def repo-root [
    repo?: path
    --init # Resolve to the current directory, without looking for cybergraph/
]: nothing -> path {
    if $repo != null {
        let expanded = $repo | path expand

        # Catch the typo here: unchecked, it surfaces later as a confusing
        # downstream error ("no pubkey registered" for a path that isn't there).
        if not ($expanded | path exists) {
            error make {msg: $"repo path does not exist: ($expanded)"}
        }
        return $expanded
    }
    nearest-home cybergraph --init=$init
}

# The deepest directory between the current one and the git root that holds
# `marker`; with none, the git root. Under --init, the current directory.
#
# Why the nearest marker and not the git root: one git repo can hold several
# homes — a monorepo carries each project it imports in a subdirectory — and
# the git root then names the wrong one, or none. Stopping at the git root
# keeps a home outside the repo out of reach.
#
# Why the candidates are built from --show-prefix and not by walking up
# `$env.PWD`: a cwd reached through a symlink names the same directory with
# another string than --show-toplevel, so an up-walk comparing the two never
# meets the git root and climbs out to `/`. git states both in one spelling.
export def nearest-home [marker: string --init]: nothing -> path {
    let result = ^git rev-parse --show-toplevel --show-prefix | complete

    if $result.exit_code != 0 {
        error make {msg: "not inside a git repository" help: "pass --repo to target one explicitly"}
    }
    let lines = $result.stdout | lines
    let toplevel = $lines.0
    let parts = $lines | get --optional 1 | default "" | path split
    let candidates = 0..($parts | length) | each {|n| $toplevel | path join ...($parts | first $n) } | reverse

    # Why init takes no part in the walk: a home above would always win, and in
    # a monorepo whose root holds one, `init` in a new project would register
    # the key into the root's trust list instead of starting a new home.
    #
    # Why refused inside the marker: there cwd is part of a home, and a new
    # home there would sit inside the old one, a stray `seal` refuses.
    if $init {
        let inside = $parts | enumerate | where item == $marker | get --optional 0.index

        if $inside != null {
            let home = $toplevel | path join ...($parts | first $inside)

            error make {msg: $"the current directory is inside ($marker)/ of ($home)" help: $"run init from ($home), or pass --repo"}
        }
        return ($candidates | first)
    }
    let found = $candidates | where ($it | path join $marker | path type) == dir

    $found | get --optional 0 | default $toplevel
}

# The graph home inside a repo: always <root>/cybergraph. One rule, no
# root-layout fallback — a second layout costs every reader forever, and a
# graph is cheap to recreate. Whole-repo attestation is plain nu-multiproof's
# job, not the graph's. Files are referenced by CID, not path, so they never need to
# live under the graph home (or in the repo at all); the seal manifest
# covers only the graph subtree.
#
# This is also where the home is checked for being one. `assert-known-home`
# refuses a top level the layout does not recognise, so a graph in a foreign or
# superseded shape stops here instead of being read as an empty one — the
# failure that made the readers answer `[]` on 301 records and let `seal` sign a
# root certifying none of them. It sits here and not in `link-files` because
# this function is the one definition of "the graph home": `link imported` walks
# a bundle through the same layout helpers, and a bundle is not a home.
export def graph-root [repo?: path]: nothing -> path {
    let root = graph-home $repo

    assert-known-home $root
    $root
}

# The same path, without asking whether what stands there is a graph home.
#
# For the one caller that must be able to read a home `graph-root` refuses:
# `strays`, whose whole job is to say what is wrong with it. A diagnostic that
# fails on the case it diagnoses is no diagnostic — and `seal`'s refusal names
# this command as the way to see the list without sealing, so it has to work
# exactly then. Split out rather than given a flag, so the path rule above
# stays stated once and the check is the only thing that varies.
export def graph-home [repo?: path]: nothing -> path {
    repo-root $repo | path join cybergraph
}
