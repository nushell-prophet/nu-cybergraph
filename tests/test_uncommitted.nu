# The store as git sees it, and the seal guard built on that reading.
#
# What is under test is one invariant: the seal manifest is every git-tracked
# file under the graph home, so a store file outside the index is bytes no root
# covers — while the link naming it is signed and frozen all the same. `particle
# uncommitted` is the reading, and `seal` refuses on it.
use std/assert
use std/testing *

use ../nu-cybergraph/init.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/particle.nu
use ../nu-cybergraph/convention.nu
use ../nu-cybergraph/seal.nu
use ../nu-cybergraph/_uncommitted.nu [ uncommitted-files stageable ]
use ../nu-cybergraph/_commit-proposal.nu [ particle-commit-line ]

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

# A git repo with an initialized graph and nothing in it yet. Committed once, so
# the working tree has a HEAD to be dirty against — a repo with no commit is a
# different git shape and not the one an operator seals in.
def empty-graph [tmp_dir: path]: nothing -> record {
    let repo = $tmp_dir | path join repo
    mkdir $repo
    ^git init --object-format=sha256 -q $repo
    ^git -C $repo config user.name t
    ^git -C $repo config user.email t@t
    let key = $tmp_dir | path join key
    ^ssh-keygen -t ed25519 -f $key -N "" -q
    ^git -C $repo config user.signingKey $key
    init --repo $repo
    ^git -C $repo add -- cybergraph
    ^git -C $repo commit -q -m init
    {repo: $repo root: ($repo | path join cybergraph) key: $key}
}

# Everything `link add` published, staged the way the proposal would stage it.
def stage-store [repo: path]: nothing -> nothing {
    ^git -C $repo add -- ($repo | path join cybergraph particles)
}

@test
def "link add leaves every byte it published outside the index" [] {
    let g = empty-graph $in.tmp_dir
    link add "cyber" "bostrom" --repo $g.repo

    let rows = uncommitted-files $g.root

    # Two files for one link: its endpoints. The edge and cyberlink addresses
    # the command reports are derived, and a derived address gets a preimage
    # only when someone publishes it (`particle add-edge` / `add-link`).
    assert equal ($rows | length) 2
    assert ($rows | all {|r| $r.state == "reachable" })
    assert ($rows | all {|r| not $r.tracked })
}

# Staged and not yet committed is the state the proposal leaves behind, and it
# is already enough: `git ls-files` reads the index, so the manifest covers
# these bytes. The rows stay — git still calls them dirty — but nothing is left
# to stage, which is the question both the proposal and the guard ask.
@test
def "a staged store file counts as tracked and leaves nothing to stage" [] {
    let g = empty-graph $in.tmp_dir
    link add "cyber" "bostrom" --repo $g.repo
    stage-store $g.repo

    let rows = uncommitted-files $g.root

    assert equal ($rows | length) 2
    assert ($rows | all {|r| $r.tracked })
    assert equal (stageable $rows) []
}

@test
def "a particle no link names is an orphan" [] {
    let g = empty-graph $in.tmp_dir
    link add "cyber" "bostrom" --repo $g.repo
    let loose = particle add "published, linked to nothing" --repo $g.repo

    let rows = uncommitted-files $g.root

    assert equal ($rows | where cid == $loose | get 0.state) "orphan"
    # Listed, and never staged: a file no link names is not in the graph, so
    # committing it is a plain `git add` and not this command's business.
    assert not ($loose in (stageable $rows | get cid))
}

# The reading has to follow the operand step, or every convention's real subject
# reads as an orphan: the record `quote` mints is the link's endpoint, and the
# quoted source is named only inside that record.
@test
def "an operand named inside an instruction record is reachable" [] {
    let g = empty-graph $in.tmp_dir
    let source = particle add "the source being quoted" --repo $g.repo
    convention quote $source "the excerpt" --repo $g.repo

    let rows = uncommitted-files $g.root

    assert equal ($rows | where cid == $source | get 0.state) "reachable"
}

# A name under particles/ that is no address used to be refused right here.
# It is refused by `strays` now — one rule over the whole graph home instead of
# this one directory — and `seal` enforces it before staging anything, which is
# the reason it ever mattered. What is pinned here is the other half of that
# move: the READING keeps reading. A reading that raises cannot tell an
# operator what is on disk, which is the one thing they need in order to fix it.
@test
def "a name under particles that is no address is reported and not refused" [] {
    let g = empty-graph $in.tmp_dir
    link add "cyber" "bostrom" --repo $g.repo
    "notes" | save --raw ($g.root | path join particles README.md)

    let rows = uncommitted-files $g.root

    assert equal ($rows | where {|r| ($r.file | path basename) == "README.md" } | get 0.cid) null
    # And the seal still refuses on it — through strays, naming the rule.
    let err = try { seal --repo $g.repo --no-stamp; null } catch {|e| $e.msg }
    assert str contains $err "not the graph layout"
    assert str contains $err "README.md"
    assert str contains $err "<cid> and <cid>.<ext> files"
}

@test
def "seal refuses while the graph names bytes git does not track" [] {
    let g = empty-graph $in.tmp_dir
    link add "cyber" "bostrom" --repo $g.repo

    let err = try { seal --repo $g.repo --no-stamp; null } catch {|e| $e.msg }

    assert str contains $err "the graph names bytes git does not track"
    assert str contains $err "particle uncommitted --propose-commit"
    # Refused before anything was staged or signed: no root was minted.
    assert not (($g.root | path join multiproofs tree-root.txt) | path exists)
}

@test
def "seal proceeds once the store is in the index" [] {
    let g = empty-graph $in.tmp_dir
    link add "cyber" "bostrom" --repo $g.repo
    stage-store $g.repo

    let sealed = seal --repo $g.repo --no-stamp

    assert equal $sealed.newborn 1
    # The whole point of the guard: the bytes the link names are in the manifest.
    let manifest = open ($g.root | path join multiproofs tree-hashes.csv) | get filepath
    assert ($manifest | any {|p| $p | str starts-with "particles/" })
}

@test
def "the flag seals without the untracked bytes" [] {
    let g = empty-graph $in.tmp_dir
    link add "cyber" "bostrom" --repo $g.repo

    let sealed = seal --repo $g.repo --no-stamp --allow-untracked-particles

    assert equal $sealed.newborn 1
    let manifest = open ($g.root | path join multiproofs tree-hashes.csv) | get filepath
    assert not ($manifest | any {|p| $p | str starts-with "particles/" })
}

@test
def "the proposal names the files it stages and the addresses they carry" [] {
    let g = empty-graph $in.tmp_dir
    let out = link add "cyber" "bostrom" --repo $g.repo

    let line = particle-commit-line (stageable (uncommitted-files $g.root)) $g.root

    assert str contains $line "particles: publish 2 files the graph names"
    assert str contains $line $out.record.cid_from
    assert str contains $line $"git -C $repo add -- "
    assert str contains $line $"particles/($out.record.cid_to)"
}

@test
def "asking for a proposal with nothing untracked to stage is refused" [] {
    let g = empty-graph $in.tmp_dir
    link add "cyber" "bostrom" --repo $g.repo
    stage-store $g.repo

    let err = try { particle uncommitted --repo $g.repo --propose-commit; null } catch {|e| $e.msg }

    assert str contains $err "nothing to propose"
}

# Never write an artifact you have not parsed back: the proposal is Nushell
# source handed to a prompt ready to run, so the only honest check is to run it
# and read what git ended up with. The seal that follows is the reason the block
# exists, so it is part of the same test.
@test
def "the proposed block runs, and the seal it unblocks covers the bytes" [] {
    let g = empty-graph $in.tmp_dir
    link add "cyber" "bostrom" --repo $g.repo

    let block = particle-commit-line (stageable (uncommitted-files $g.root)) $g.root
    let run = do { ^nu --commands $block } | complete
    assert equal $run.exit_code 0 $"the proposed block did not run: ($run.stderr)"

    assert equal (uncommitted-files $g.root) []
    let committed = ^git -C $g.repo show --name-only --format= HEAD | lines | where $it != ""
    assert equal ($committed | length) 2
    assert ($committed | all {|f| $f | str starts-with "cybergraph/particles/" })

    let sealed = seal --repo $g.repo --no-stamp
    let manifest = open ($g.root | path join multiproofs tree-hashes.csv) | get filepath
    assert equal ($manifest | where {|p| $p | str starts-with "particles/" } | length) 2
    assert equal $sealed.newborn 1
}

@test
def "the public reading shows paths a reader can open" [] {
    let g = empty-graph $in.tmp_dir
    link add "cyber" "bostrom" --repo $g.repo

    let rows = particle uncommitted --repo $g.repo

    assert equal ($rows | columns) [file cid size state tracked]
    assert ($rows | all {|r| $r.file | path exists })
}
