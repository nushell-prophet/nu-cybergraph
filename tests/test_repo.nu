use std/assert
use std/testing *

use ../nu-cybergraph/init.nu
use ../nu-cybergraph/_repo.nu [ repo-root graph-root ]

# A git repo at <tmp>/outer with a project at outer/project/deep: the
# monorepo shape the default exists for. Paths come back from git, so the
# fixture resolves the tmp dir the same way before comparing.
@before-each
def setup []: nothing -> record {
    let tmp_dir = mktemp --directory
    let outer = $tmp_dir | path join outer

    mkdir ($outer | path join project deep)
    ^git -C $outer init --quiet
    let outer = ^git -C $outer rev-parse --show-toplevel | str trim

    {tmp_dir: $tmp_dir outer: $outer project: ($outer | path join project)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

@test
def "the nearest cybergraph dir above the current directory names the graph" [] {
    let outer = $in.outer
    let project = $in.project

    mkdir ($outer | path join cybergraph) ($project | path join cybergraph)
    cd ($project | path join deep)
    assert equal (repo-root) $project
    assert equal (graph-root) ($project | path join cybergraph)
}

# Run from inside the home, the walk meets the home's parent first: the
# home itself holds no cybergraph/.
@test
def "inside the graph home the default is the repo that holds it" [] {
    let project = $in.project

    mkdir ($project | path join cybergraph certs)
    cd ($project | path join cybergraph certs)
    assert equal (repo-root) $project
}

@test
def "with no cybergraph dir the default is the git root" [] {
    let outer = $in.outer

    cd ($in.project | path join deep)
    assert equal (repo-root) $outer
}

@test
def "an explicit repo wins over a cybergraph dir in the current directory" [] {
    let outer = $in.outer
    let project = $in.project

    mkdir ($project | path join cybergraph)
    cd $project
    assert equal (repo-root $outer) $outer
}

# The user-visible half of --init: a new graph lands where the operator
# stands, not at the root of a monorepo that holds other projects.
@test
def "init with no graph found creates the home in the current directory" [] {
    let tmp_dir = $in.tmp_dir
    let outer = $in.outer
    let project = $in.project
    let key = $tmp_dir | path join key

    ^ssh-keygen -t ed25519 -f $key -N "" -q
    ^git -C $outer config user.signingKey $key
    cd $project
    init

    assert ($project | path join cybergraph certs | path exists) "init did not create the home in the current directory"
    assert not ($outer | path join cybergraph | path exists) "init created a home at the git root"
}

# A re-run from inside the home must not build a second home inside the first:
# the closed tree has no place for it, and `seal` would refuse it as a stray.
@test
def "init from inside a graph home is refused and creates nothing" [] {
    let tmp_dir = $in.tmp_dir
    let outer = $in.outer
    let project = $in.project
    let key = $tmp_dir | path join key

    ^ssh-keygen -t ed25519 -f $key -N "" -q
    ^git -C $outer config user.signingKey $key
    cd $project
    init
    cd ($project | path join cybergraph certs)
    let err = try { init; null } catch {|e| $e.msg }

    assert ($err != null) "init ran inside a graph home"
    assert str contains $err "--repo"
    assert not ($project | path join cybergraph certs cybergraph | path exists) "a refused init still created a nested home"
}

# The monorepo case: a graph at the root does not take over `init` in a new
# project below it.
@test
def "init below an existing graph starts a new home in the current directory" [] {
    let tmp_dir = $in.tmp_dir
    let outer = $in.outer
    let project = $in.project
    let key = $tmp_dir | path join key

    ^ssh-keygen -t ed25519 -f $key -N "" -q
    ^git -C $outer config user.signingKey $key
    init --repo $outer
    cd $project
    init

    assert ($project | path join cybergraph certs | path exists) "init did not create the home in the current directory"
}

# The cases below repeat nu-multiproof's tests for its copy of nearest-home:
# the code is duplicated, so a change in this copy is untested without them.

@test
def "a cybergraph file is not a home" [] {
    let outer = $in.outer
    let project = $in.project

    "" | save ($project | path join cybergraph)
    cd $project
    assert equal (repo-root) $outer
}

# The walk stops at the git root: a home in a directory that contains the
# repo is another project, not this one.
@test
def "a cybergraph dir above the git root is out of reach" [] {
    let outer = $in.outer

    mkdir ($in.tmp_dir | path join cybergraph)
    cd $outer
    assert equal (repo-root) $outer
}

# The case that rules out walking `$env.PWD` up to the git root: through a
# symlink the two spell one directory differently, and that walk never stops.
@test
def "a current directory reached through a symlink resolves inside the repo" [] {
    let project = $in.project
    let link = $in.tmp_dir | path join link

    mkdir ($project | path join cybergraph)
    ^ln --symbolic $project $link
    cd ($link | path join deep)
    assert equal (repo-root) $project
}

@test
def "outside a git repo the default fails and names the flag" [] {
    cd $in.tmp_dir
    let err = try { repo-root; null } catch {|e| $e.msg }

    assert str contains $err "--repo"
}
