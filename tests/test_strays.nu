# The graph home is a closed set: SPEC section 3 draws the whole tree, and
# nothing else may sit under it.
#
# The failure this exists for, measured before the check was written: with the
# graph in the superseded `links/<link-cid>.json` layout, `link list`,
# `link touching` and `link tally` all answered `[]` at exit 0 — 301 records
# read as none — while `particle uncommitted` called every particle an orphan
# and `seal` SUCCEEDED, signing a merkle root for a graph whose links it could
# not see and certifying none of them. A reader that finds nothing must fail
# rather than call it an empty graph.
use std/assert
use std/testing *

use ../nu-cybergraph/init.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/particle.nu
use ../nu-cybergraph/seal.nu
# `strays.nu` exports the command as the bare name, so the layout function it
# wraps is imported under its module prefix rather than shadowing it.
use ../nu-cybergraph/strays.nu
use ../nu-cybergraph/_layout.nu
use ../nu-cybergraph/_layout.nu [ assert-known-home ]

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

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

# --- the home is recognised, or nothing is read ---

@test
def "a graph in the superseded links layout is refused and not read as empty" [] {
    let g = empty-graph $in.tmp_dir
    let added = link add "cyber" "bostrom" --repo $g.repo

    # Rewrite the store into the pre-signer-directory shape: one flat
    # `links/` directory, exactly what the old tool wrote.
    mkdir ($g.root | path join links)
    open --raw $added.path | save --raw ($g.root | path join links $"($added.edge_cid).json")
    rm --recursive --force ($added.path | path dirname)

    for reading in [
        {|| link list --repo $g.repo }
        {|| link touching "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG" --repo $g.repo }
        {|| link tally "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG" --repo $g.repo }
    ] {
        let err = try { do $reading; null } catch {|e| $e.msg }

        assert not ($err | is-empty) "a reading answered instead of refusing an unknown home"
        assert str contains $err "unknown graph home"
        assert str contains $err "links"
    }
}

@test
def "a seal over a graph in the superseded layout mints no root" [] {
    let g = empty-graph $in.tmp_dir
    let added = link add "cyber" "bostrom" --repo $g.repo

    mkdir ($g.root | path join links)
    open --raw $added.path | save --raw ($g.root | path join links $"($added.edge_cid).json")
    rm --recursive --force ($added.path | path dirname)

    let err = try { seal --repo $g.repo --no-stamp; null } catch {|e| $e.msg }

    assert str contains $err "unknown graph home"
    # The whole point: no signed root for links nothing verified.
    assert not (($g.root | path join multiproofs tree-root.txt) | path exists)
}

@test
def "a hand-written file at the graph root is refused" [] {
    let g = empty-graph $in.tmp_dir

    "notes to self" | save --raw ($g.root | path join README.md)

    let err = try { link list --repo $g.repo; null } catch {|e| $e.msg }

    assert str contains $err "unknown graph home"
    assert str contains $err "README.md"
}

@test
def "the proof directory is not a stray" [] {
    let g = empty-graph $in.tmp_dir

    link add "cyber" "bostrom" --repo $g.repo

    # multiproofs/ sits inside the graph home and is nu-multiproof's, so it is
    # recognised at the top and walked nowhere.
    assert equal (_layout strays $g.root) []
    assert equal (link list --repo $g.repo | length) 1
}

# --- the deep reading ---

@test
def "strays names the path the directory and what that directory allows" [] {
    let g = empty-graph $in.tmp_dir

    mkdir ($g.root | path join particles)
    "notes" | save --raw ($g.root | path join particles README.md)

    let rows = _layout strays $g.root

    assert equal ($rows | length) 1
    assert equal ($rows | get 0.path | path basename) "README.md"
    assert equal ($rows | get 0.under | path basename) "particles"
    assert str contains ($rows | get 0.allowed) "<cid> and <cid>.<ext> files"
}

@test
def "a name that is no address is a stray in every directory that addresses its files" [] {
    let g = empty-graph $in.tmp_dir
    let added = link add "cyber" "bostrom" --repo $g.repo
    let signer_dir = $added.path | path dirname

    "x" | save --raw ($signer_dir | path join "notes.json")
    "x" | save --raw ($g.root | path join particles "notes.txt")
    mkdir ($g.root | path join certs "not-a-cid")
    mkdir ($g.root | path join seals "NOTHEX")
    mkdir ($g.root | path join receipts "not-a-cid")
    mkdir ($g.root | path join order "not-a-cid")
    # The run is addressed the same way the links are, so a name that is no
    # address is a stray there too — `link add` has already made the signer's
    # own order directory, and this file sits beside its position.
    "x" | save --raw ($g.root | path join order ($signer_dir | path basename) "notes.order.json")

    let rows = _layout strays $g.root

    assert equal ($rows | get path | path basename | sort) (
        ["NOTHEX" "not-a-cid" "not-a-cid" "not-a-cid" "notes.json" "notes.order.json" "notes.txt"]
    )
}

@test
def "a clean graph has no strays and the reading is the command" [] {
    let g = empty-graph $in.tmp_dir

    link add "cyber" "bostrom" --repo $g.repo
    particle add "a thesis" --repo $g.repo --literal | ignore

    assert equal (_layout strays $g.root) []
    assert equal (strays --repo $g.repo) []
}

@test
def "what a bundle holds inside is not this rule to enforce" [] {
    let g = empty-graph $in.tmp_dir
    let added = link add "cyber" "bostrom" --repo $g.repo
    let signer = $added.path | path dirname | path basename
    let bundle = $g.root | path join exports $signer $added.edge_cid

    mkdir ($bundle | path join particles)
    "anything at all" | save --raw ($bundle | path join "README.md")

    # A bundle is a self-contained artifact `verify-bundle` checks as a whole.
    # Naming its contents here would be this module asserting a layout it does
    # not own — the same mistake as policing multiproofs/.
    assert equal (_layout strays $g.root) []
}

# The reading has to survive the very thing the refusal is about. `seal`'s
# refusal names this command as the way to see the list without sealing, so a
# `strays` that failed on an unrecognised top level would be no diagnostic at
# all — it would fail exactly when it is needed. Written after the first
# version did precisely that, because it resolved the home through
# `graph-root`.
@test
def "the reading survives a top level the refusal rejects" [] {
    let g = empty-graph $in.tmp_dir
    let added = link add "cyber" "bostrom" --repo $g.repo

    mkdir ($g.root | path join links)
    open --raw $added.path | save --raw ($g.root | path join links $"($added.edge_cid).json")

    # A reading of the graph refuses...
    let err = try { link list --repo $g.repo; null } catch {|e| $e.msg }

    assert str contains $err "unknown graph home"

    # ...and the command that says why does not.
    let rows = strays --repo $g.repo

    assert equal ($rows | get path | path basename) ["links"]
    assert str contains ($rows | get 0.allowed) "<signer-cid>/ directories"
}

@test
def "an absent graph home is not an unknown one" [] {
    let bare = $in.tmp_dir | path join nothing-here

    assert equal (_layout strays $bare) []
    assert-known-home $bare
}
