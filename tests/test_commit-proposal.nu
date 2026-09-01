# What `seal --propose-commit` puts in the prompt.
#
# The wording tests pin the message against a hand-built seal result: the point
# is that the body says a known thing for a known input, and a round-trip through
# `seal` would only prove the proposal agrees with whatever seal returns today.
# The quoting tests then push hostile paths through Nushell's own parser, since
# this copy of `quote-arg` carries its guarantee on its own. The last two seal a
# real graph: one that asking for the proposal changes nothing about the seal,
# one that runs the block and reads back what git ended up with.
#
# Every seal here passes --allow-untracked-particles. None of these tests is
# about the store's own commit discipline, and they never commit anything: the
# guard `seal` grew would otherwise refuse them all, for a reason each of them
# has already agreed to ignore. tests/test_uncommitted.nu is where the guard itself
# is under test, both ways.
use std/assert
use std/testing *

use ../nu-cybergraph/init.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/seal.nu
use ../nu-cybergraph/_commit-proposal.nu [ seal-commit-line quote-arg ]
use ../nu-cybergraph/_signer.nu [ own-signer ]

const P1 = "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
const P2 = "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
const ROOT = "ee947cd6a1f3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a3b4c"

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

# What a stamped seal returns, with the fields the proposal reads. `/graph` never
# exists on disk, which is deliberate for the wording tests: the staged pathspec
# is then empty and the message is all that is under test. The real staged set is
# pinned by the last test, against a graph that exists.
def stamped-result []: nothing -> record {
    {
        sealed: {
            manifest: "/graph/multiproofs/tree-hashes.csv"
            root_cid: "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
            merkle_root: $ROOT
            root_sig: "/graph/multiproofs/tree-root.txt.abc.sig"
            bundle: "/graph/multiproofs/ots-timestamps/tree-root.EE947CD6"
            sig_ots: ["/graph/multiproofs/ots-timestamps/tree-root.EE947CD6/tree-root.txt.abc.ots"]
        }
        newborn: 2
        receipts: 1
        positions: 2
        numbered: 0
        snapshot: "cybergraph/seals/ee947cd6a1f3"
    }
}

# A git repo with an initialized graph holding one link. Returns the repo, the
# graph home and the key registered as its identity.
def graph-with-a-link [tmp_dir: path]: nothing -> record {
    let repo = $tmp_dir | path join repo
    mkdir $repo
    ^git init --object-format=sha256 -q $repo
    ^git -C $repo config user.name t
    ^git -C $repo config user.email t@t
    let key = $tmp_dir | path join key
    ^ssh-keygen -t ed25519 -f $key -N "" -q
    ^git -C $repo config user.signingKey $key
    init --repo $repo
    link add $P1 $P2 --repo $repo --allow-missing
    {repo: $repo root: ($repo | path join cybergraph) key: $key}
}

@test
def "the subject carries the first 8 hex of the merkle root" [] {
    let line = seal-commit-line (stamped-result) "/graph" "QmSigner"

    # The trailing newline is part of the match on purpose: it is what pins the
    # truncation. The full root is in the body, so a plain `str contains` of the
    # 8 characters would pass even if the subject carried all 64 — and 64 hex
    # characters push everything else off a `git log --oneline` line.
    assert str contains $line $'let msg = "seal: graph catalogued at merkle root ee947cd6(char newline)'
}

# `seal` always stamps with --no-content-anchor, so the endorsement anchor is the
# only one there is. Upstream's "content + N" form must never appear here.
@test
def "a stamped seal names its bundle and reports the endorsement anchor alone" [] {
    let line = seal-commit-line (stamped-result) "/graph" "QmSigner"

    assert str contains $line "Bundle: multiproofs/ots-timestamps/tree-root.EE947CD6"
    assert str contains $line "Anchors: 1 endorsement, pending until Bitcoin confirms"
    assert not ($line | str contains "content +")
}

@test
def "two signatures are counted, and read as plural" [] {
    let two = stamped-result | update sealed.sig_ots {|r| $r.sealed.sig_ots | append "/graph/x.ots" }

    assert str contains (seal-commit-line $two "/graph" "QmSigner") "Anchors: 2 endorsements"
}

@test
def "a seal with no stamp reports no anchor and names no bundle" [] {
    let unstamped = stamped-result | update sealed {|r| $r.sealed | reject bundle sig_ots }

    let line = seal-commit-line $unstamped "/graph" "QmSigner"

    assert str contains $line "Anchors: none, sealed with --no-stamp"
    # A bundle line here would name a directory the seal never wrote.
    assert not ($line | str contains "Bundle:")
}

@test
def "the certificates this seal froze are counted by kind" [] {
    let line = seal-commit-line (stamped-result) "/graph" "QmSigner"

    assert str contains $line "Froze: 2 birth certificates, 1 receipt certificate, 2 position proofs"
}

# A repeated seal certifies nothing new — it only re-attests what earlier roots
# already carried. Stated, not omitted: a missing line reads as a forgotten field.
@test
def "a seal that froze nothing says so instead of dropping the line" [] {
    let nothing_new = stamped-result | update newborn 0 | update receipts 0 | update positions 0

    assert str contains (seal-commit-line $nothing_new "/graph" "QmSigner") "Froze: nothing new"
}

@test
def "a link with no receipt names only the birth certificate" [] {
    let one = stamped-result | update newborn 1 | update receipts 0 | update positions 0

    let line = seal-commit-line $one "/graph" "QmSigner"

    assert str contains $line "Froze: 1 birth certificate\n"
    assert not ($line | str contains "receipt certificate")
}

# Numbering is an EDIT to files the operator wrote — the claimed time is
# replaced by the number the run gives it — so the commit carrying it has to say
# so. A re-seal numbers nothing, and a line stating that on every seal would be
# a constant, so it appears only when something was numbered.
@test
def "a numbered position is named in the body and silence is the ordinary case" [] {
    assert not ((seal-commit-line (stamped-result) "/graph" "QmSigner") | str contains "Numbered")

    let minted = stamped-result | update numbered 2

    assert str contains (seal-commit-line $minted "/graph" "QmSigner") "Numbered: 2 provisional positions"
}

# The snapshot is where every certificate frozen under this root verifies against,
# so the body must name the one this seal wrote — derived from the root, the same
# way `bundle` looks it up.
@test
def "the snapshot is derived from the root, not read off the seal result" [] {
    # What `seal` returns is relative to wherever it was RUN from, and a commit
    # body is read from anywhere. So this field must not be the source.
    let elsewhere = stamped-result | update snapshot "../../somewhere/else"

    let line = seal-commit-line $elsewhere "/graph" "QmSigner"

    assert str contains $line "Snapshot: seals/ee947cd6a1f3"
    assert not ($line | str contains "somewhere/else")
}

@test
def "the signer is the CID passed in, not anything read off a filename" [] {
    let cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"

    # The result's own .sig path says "abc" — the proposal must ignore it.
    let line = seal-commit-line (stamped-result) "/graph" $cid

    assert str contains $line $"Signed by: ($cid)"
    assert not ($line | str contains "Signed by: abc")
}

@test
def "the message body is real lines, not escapes" [] {
    let line = seal-commit-line (stamped-result) "/graph" "QmSigner"

    # The operator is meant to edit this before running it, and a body escaped
    # into `\n` inside a quoted argument is the one shape that cannot be edited
    # comfortably. So the escape must NOT be there.
    assert not ($line | str contains '\nMerkle root: ')
    assert str contains $line "\nMerkle root: "
    # The `let repo` line, subject, blank line, seven body lines, blank line,
    # two git lines.
    assert equal ($line | lines | length) 13
}

# `quote-arg` is this repo's own copy, not an import of nu-multiproof's, so its
# guarantee has to be pinned here: the block PARSES as one command with one
# argument, whatever the path holds. Round-tripped through Nushell itself rather
# than compared to an expected spelling — what matters is that the parser returns
# the original bytes, not how `to nuon` chose to spell them.
@test
def "a graph path holding a quote still parses as one argument" [] {
    # Hostile input, not a round-trip: a path is data, and this string is handed
    # to the prompt ready to run. Nothing in this repo produces such a path —
    # that is the point of building it by hand.
    let nasty = '/tmp/we"ird\path'

    let quoted = quote-arg $nasty

    assert equal ($quoted | lines | length) 1
    let round_tripped = ^nu --commands $"print --raw ($quoted)" | str trim --right --char "\n"
    assert equal $round_tripped $nasty
}

@test
def "multiline mode keeps newlines but still escapes a quote" [] {
    # The message body is the one place a newline is meant. A quote in it would
    # still end the string early, so only the newline rule relaxes.
    let body = "line one\nhe said \"hi\"\nline three"

    let quoted = quote-arg $body --multiline

    assert equal ($quoted | lines | length) 3
    let round_tripped = ^nu --commands $"print --raw ($quoted)" | str trim --right --char "\n"
    assert equal $round_tripped $body
}

@test
def "a newline in a path cannot break out of the quoted argument" [] {
    # Without the escape the second line would be its own command in a prompt the
    # operator is about to press enter on.
    let nasty = "/tmp/a\nrm -rf /"

    let quoted = quote-arg $nasty

    assert equal ($quoted | lines | length) 1
    let round_tripped = ^nu --commands $"print --raw ($quoted)" | str trim --right --char "\n"
    assert equal $round_tripped $nasty
}

# `commandline edit` only reaches a prompt from the REPL. Outside one it still
# writes the engine's repl buffer — harmless, not a no-op — and only the REPL
# reads that back, so the flag is inert in a script without being an error.
# "Inert" is a claim about a command that runs, so it is pinned rather than
# assumed: what the proposal SAYS is tested above, this pins only that asking for
# it changes nothing else about the seal.
@test
def "asking for a commit proposal leaves the seal result untouched" [] {
    let g = graph-with-a-link $in.tmp_dir

    let plain = seal --repo $g.repo --no-stamp --allow-untracked-particles
    let proposed = seal --repo $g.repo --no-stamp --allow-untracked-particles --propose-commit

    # Not the same record: a second seal mints a new root, and with it a new
    # snapshot — that is what "a repeated seal is not a no-op" means. What must
    # match is the shape and the freeze counts, both seals having nothing newborn
    # left to certify.
    assert equal ($proposed | columns) ($plain | columns)
    assert equal $proposed.newborn 0
    assert equal $proposed.receipts $plain.receipts
}

# Never write an artifact you have not parsed back. The proposal is Nushell source
# handed to a prompt ready to run, so the only honest check is to run it and read
# what git ended up with — a string assertion proves the builder agrees with
# itself, never that the block parses.
@test
def "the proposed block runs and commits exactly what the seal wrote" [] {
    let g = graph-with-a-link $in.tmp_dir
    let result = seal --repo $g.repo --no-stamp --allow-untracked-particles
    let root_hex = $result.sealed.merkle_root
    let signer = own-signer $g.root

    # `complete` so git's own chatter stays out of the test report — and so a
    # failure reports the block's stderr, which a bare throw would drop.
    let run = do { ^nu --commands (seal-commit-line $result $g.root $signer) } | complete
    assert equal $run.exit_code 0 $"the proposed block did not run: ($run.stderr)"

    let message = ^git -C $g.repo log -1 --format=%B
    assert str contains $message $"seal: graph catalogued at merkle root ($root_hex | str substring 0..<8)"
    assert str contains $message $"Merkle root: ($root_hex)"
    assert str contains $message $"Signed by: ($signer)"
    assert str contains $message "Froze: 1 birth certificate"
    assert str contains $message $"Snapshot: seals/($root_hex | str substring 0..11)"
    # A blank line between subject and body, or `git log --oneline` prints the
    # whole record as the subject.
    assert equal ($message | lines | get 1) ""

    # The seal's own artifacts landed, and nothing outside the graph home.
    let committed = ^git -C $g.repo show --name-only --format= HEAD | lines | where $it != ""
    assert ($committed | all {|f| $f | str starts-with "cybergraph/" })
    assert ($committed | any {|f| $f | str starts-with $"cybergraph/($signer)/" })
    assert ($committed | any {|f| $f | str starts-with "cybergraph/certs/" })
    assert ($committed | any {|f| $f | str starts-with "cybergraph/seals/" })
    assert ($committed | any {|f| $f == "cybergraph/multiproofs/tree-root.txt" })

    # Nothing is left staged: the proposal's pathspec has to cover every path the
    # seal touched, deletions included.
    assert equal (^git -C $g.repo diff --cached --name-only | str trim) ""
}
