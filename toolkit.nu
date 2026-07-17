# Entry point stub — the tasks are the `main <task>` subcommands below.
export def main [] { }

# Requires a nutest checkout at ../../ai-sandbox-dev-container/nutest — the
# same live-sibling convention as the nu-multiproof dependency (_deps.nu).
export def 'main test' [--fail] {
    use ../../ai-sandbox-dev-container/nutest/nutest

    if $fail {
        nutest run-tests --path tests/ --fail
    } else {
        nutest run-tests --path tests/
    }
}
