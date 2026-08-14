# Entry point stub — the tasks are the `main <task>` subcommands below.
export def main [] { }

# Requires nutest as a sibling at ../nutest — the same live-sibling convention
# as the nu-multiproof dependency (_deps/). In the monorepo that sibling is a
# symlink to the one checkout outside it, which other modules also use: the
# path is uniform here, and nothing had to move.
export def 'main test' [--fail] {
    use ../nutest/nutest

    nutest run-tests --path tests/ --fail=$fail
}
