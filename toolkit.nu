# Entry point stub — the tasks are the `main <task>` subcommands below.
export def main [] { }

# Requires nutest as a sibling at ../nutest — the same live-sibling convention
# as the nu-multiproof dependency (_deps/). In the monorepo that sibling is a
# symlink to the one checkout outside it, which other modules also use: the
# path is uniform here, and nothing had to move.
#
# Why one thread by default: nutest's own default runs every suite in parallel
# and every test inside it in parallel too. Under Apple `container` that spawn
# density wedges the terminal of the whole VM — the guest keeps working, but
# nothing it prints reaches the screen until the machine is restarted. Measured
# on nu-multiproof, whose suite has the same shape: thirty single-threaded runs
# never wedged, the parallel form went down on the fourth or fifth. The fault is
# in the runtime rather than here, so this default should go once it is fixed
# upstream. Pass --threads 0 for the old behaviour (0 means one per core).
# The investigation is not on any live branch — it lives in an archived tag of
# the cozy repo: git show archive/debug-freeze:todo/20260830-debug-freeze.md
export def 'main test' [
    --fail
    --threads: int = 1 # nutest worker threads; 1 by default for the reason above, 0 means one per core
] {
    use ../nutest/nutest

    nutest run-tests --path tests/ --strategy {threads: $threads} --fail=$fail
}
