# End-to-end: signer A births a link, seals, exports the bundle; signer B
# verifies and imports it offline. Ports the bostrom-journal bj003 smoke
# experiment into a pinned test.
#
# Offline throughout. Most seals pass --no-stamp and skip stamping; a few pass
# --response-file, which feeds the calendar's answer from a local fixture and so
# reaches a real (pending) stamp with no network. A calendar can only ever answer
# pending, so the anchored case is reached by building a Bitcoin attestation here
# — the one OTS byte format this file writes for itself.
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
use ../nu-cybergraph/bundle.nu
use ../nu-cybergraph/import.nu
use ../nu-cybergraph/verify.nu
use ../nu-cybergraph/verify-bundle.nu
use ../nu-cybergraph/convention.nu
use ../nu-cybergraph/particle.nu
use ../nu-cybergraph/_derive.nu [record-bytes]
use ../nu-cybergraph/_verify-helpers.nu [stamp-cell]
use ../nu-cybergraph/_fs.nu [list-files list-dirs]
use ../nu-cybergraph/_deps/cid-v0.nu [cid-v0]
use ../nu-cybergraph/_deps/pubkey.nu [pubkey]
use ../nu-cybergraph/_deps/ssh-sign.nu [ssh-sign]

const P1 = "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
const P2 = "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

# A signer repo: sha256 git backend (the spec's recommendation), one key
# registered as both git signing key and cybergraph identity.
#
# --key-type exists for one case: ed25519 signatures are deterministic (RFC
# 8032), so re-signing the same bytes with the same key reproduces the same
# signature file. A test that needs one key to hold TWO different valid
# signatures over one root must use a randomized algorithm — ecdsa here, which is
# also what the editor's own ecdsa-sk key does in the field.
def make-signer [tmp_dir: path name: string --key-type: string = "ed25519"]: nothing -> record {
    let repo = $tmp_dir | path join $name
    mkdir $repo
    ^git init --object-format=sha256 -q $repo
    ^git -C $repo config user.name $name
    ^git -C $repo config user.email $"($name)@test"
    let key = $tmp_dir | path join $"key-($name)"
    ^ssh-keygen -t $key_type -f $key -N "" -C $name -q
    ^git -C $repo config user.signingKey $key
    init --repo $repo
    {repo: $repo home: ($repo | path join cybergraph) key: $key pub: $"($key).pub"}
}

@test
def "birth, seal, bundle, import, verify — the full link journey" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"

    # Birth + seal: certificate frozen, root snapshot archived
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    let sealed = seal --repo $a.repo --no-stamp --allow-untracked-particles
    assert equal $sealed.newborn 1
    assert (($a.home | path join certs $born.record.signer $"($born.edge_cid).cert.json") | path exists)
    assert (($sealed.snapshot | path join tree-root.txt) | path exists)
    assert ((glob ($sealed.snapshot | path join "tree-root.txt.*.sig") | length) == 1)

    # Own-link verify goes through the same bundle path a stranger would use;
    # the result is a one-row table — same shape as the imported case below
    let owns = verify $born.edge_cid --repo $a.repo
    assert equal ($owns | length) 1
    let own = $owns | first
    assert $own.valid
    assert $own.signer.bound
    assert equal $own.record $born.record
    # One anchor, one claim: when the signer endorsed this. Upstream's `ots` —
    # the content anchor — is dropped rather than reported as permanently
    # `absent`, which would read as "this link has no timestamp".
    assert ("ots" not-in ($own | columns)) "the content anchor is back in the verify record"
    # Under --no-stamp the endorsement is `absent` — real, and nobody stamped it
    # — but `endorsed` is a RECORD and not null, which is what says a valid
    # signature by the claimed signer exists at all.
    assert equal $own.signer.endorsed.status "absent"

    # Export and import into B
    let bundle_dir = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out-bundle)
    let b = make-signer $tmp_dir "b"
    let imported = import $bundle_dir --repo $b.repo
    assert equal $imported.signer $born.record.signer
    assert (($b.home | path join imported $born.record.signer $born.edge_cid) | path exists)

    # B verifies its copy offline, by CID alone
    let checks = verify $born.edge_cid --repo $b.repo
    assert equal ($checks | length) 1
    assert ($checks | first | get valid)
    assert ($checks | first | get signer.bound)

    # B's own seal catalogues the imported bundle — the custody layer:
    # "this signer held the link no later than block K"
    seal --repo $b.repo --no-stamp --allow-untracked-particles | ignore
    let b_manifest = open --raw ($b.home | path join multiproofs tree-hashes.csv)
        | from csv --no-infer
    let bundled_record = $"imported/($born.record.signer)/($born.edge_cid)/($born.record.signer)/($born.edge_cid).json"
    assert ($b_manifest | where filepath == $bundled_record | is-not-empty)

    # A second seal must not touch the frozen certificate (birth, not latest)
    let cert = $a.home | path join certs $born.record.signer $"($born.edge_cid).cert.json"
    let before = open --raw $cert | hash sha256
    link add $P2 $P1 --repo $a.repo --allow-missing
    let sealed2 = seal --repo $a.repo --no-stamp --allow-untracked-particles
    assert equal $sealed2.newborn 1
    assert equal (open --raw $cert | hash sha256) $before
    # ...and the old link still verifies against its archived root
    assert (verify $born.edge_cid --repo $a.repo | first | get valid)
}

# bj002's own point about instructions: the record names cid_from/cid_to, but
# without their bytes an importer holds an address and not the preimage —
# gm-vote's connector had to fall back to scanning particles/ across every
# local repo it could reach to decode a verb like {"op":"agree"}. So a bundle
# now carries the ends it holds a file for, by default; --links-only is the
# escape hatch back to the old, particle-free shape.
@test
def "bundle carries the ends particles by default, links-only drops them" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add "cyber" "bostrom" --repo $a.repo
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore

    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)
    let particle_names = list-files ($out | path join particles) | each { path basename }
    assert equal ($particle_names | sort) ([$born.record.cid_from $born.record.cid_to] | sort)
    assert equal (open --raw ($out | path join particles $born.record.cid_from)) "cyber"
    assert equal (open --raw ($out | path join particles $born.record.cid_to)) "bostrom"

    # The trip still verifies with the extra files, and imports clean.
    let v = verify-bundle $out
    assert $v.valid
    let b = make-signer $tmp_dir "b"
    import $out --repo $b.repo | ignore

    let links_only_out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out-links-only) --links-only
    assert not (($links_only_out | path join particles) | path exists)
    assert (verify-bundle $links_only_out | get valid)

    # An end whose bytes are not local — P1/P2 are bare CID strings, never
    # published as particle files — is silently skipped: a cyberlink naming a
    # CID the bytes need not be local for is legitimate, so `bundle` ships
    # whatever preimages it actually holds, not a promise every end resolves.
    let unresolved = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out_unresolved = bundle $unresolved.edge_cid --repo $a.repo --out ($tmp_dir | path join out-unresolved)
    assert not (($out_unresolved | path join particles) | path exists)
}

# A bundle arriving without its record is refused either way — this is about
# WHICH refusal. `merkle verify` resolves the leaf, finds nothing there, and
# returns a row saying so; `verify-bundle` then opened the same absent path and
# died with `nu::shell::io::not_found`, throwing away the verdict the layer
# below had already computed. Through `verify` the operator saw two words,
# `File not found`, with no path, no bundle and no link.
@test
def "a bundle whose record file is absent returns a verdict, not a crash" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    rm ($out | path join $born.record.signer $"($born.edge_cid).json")

    let v = verify-bundle $out
    assert not $v.valid
    # The reason names the file, and it is upstream's — not a second copy of
    # the same rule written here.
    assert ($v.error | str contains $born.edge_cid) $"the error does not name the leaf: ($v.error)"
    assert ($v.error | str contains "absent on disk") $"the error does not say what is wrong: ($v.error)"
    # The shape is the shape every other verdict has, so a caller reading the
    # record never branches on how the bundle failed.
    assert equal $v.record null
    assert not $v.signer.bound
    assert equal $v.custody []
    assert ("ots" not-in ($v | columns)) "the content anchor is back in the verify record"

    # And the refusal survives the layer above: `import` reports it as a
    # refusal to import, not as a crash.
    let b = make-signer $tmp_dir "b"
    let err = try { import $out --repo $b.repo; null } catch {|e| $e.msg }
    assert ($err | str contains "refusing to import") $"import did not refuse cleanly: ($err)"
}

# The one failure here that produced a self-consistent lie. `cp` reports an
# unreadable source on stderr and exits 0, so an import could land short; the
# receipt's `files` manifest is recomputed FROM the landed copy, so it then
# committed to the truncation, and every verification afterwards passed over
# missing bytes. Nothing in the artifact recorded that anything was lost.
#
# Mode 000 and not a deleted file: a MISSING source does raise, which is why
# this looked unreproducible at first. Unreadable is the case that is silent.
@test
def "an import that could not copy every file is refused, not truncated" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    # An extra file in the bundle that the importer cannot read. It is not part
    # of the proof, which is the point: the loss has to be caught by the copy,
    # because no verification downstream would ever miss it.
    let unreadable = $out | path join extra.txt
    "bytes the recipient must not silently lose\n" | save --raw $unreadable
    ^chmod 000 $unreadable

    let b = make-signer $tmp_dir "b"
    let err = try { import $out --repo $b.repo; null } catch {|e| $e.msg }
    ^chmod 644 $unreadable
    assert ($err != null) "import succeeded over a file it could not copy"
    assert ($err | str contains "extra.txt") $"the refusal does not name the lost file: ($err)"
    # And no receipt, and no half-built copy: a refused import commits to
    # nothing and leaves nothing. The stranded copy would matter — `import`
    # refuses a destination that already exists, so it would make the retry
    # impossible inside a tree this repo calls read-only.
    assert not (($b.home | path join receipts ($born.record.signer) $"($born.edge_cid).receipt.json") | path exists)
    assert not (($b.home | path join imported $born.record.signer $born.edge_cid) | path exists)
}

# `verify` on an own link builds a bundle in a temp dir and cleans it up. The
# cleanup used to re-raise a reconstruction of the error instead of the error,
# so everything below the top frame was dropped: with ssh-keygen off PATH the
# operator saw `Eval block failed with pipeline input` and nothing about
# OpenSSH, and diagnosing it took a bypass around `verify`.
#
# Asserted on `debug`, not on `msg`: `msg` is nushell's own wrapper text either
# way, because the raise happens inside an `each` several frames down. The
# chain is what the rewrap destroyed, and `debug` is where the chain is.
@test
def "a verify that fails deep still carries the real cause" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore

    # A PATH holding git and nothing else. Reading the bundle's pubkeys needs
    # ssh-keygen, so the failure lands well below `verify` — which is the only
    # kind of failure the old rewrap could destroy.
    let bin = $tmp_dir | path join bin
    mkdir $bin
    ^ln -sf (which git | get 0.path) ($bin | path join git)
    let err = with-env {PATH: [$bin]} {
        try { verify $born.edge_cid --repo $a.repo; null } catch {|e| $e.debug }
    }
    assert ($err != null) "verify succeeded with no ssh-keygen on PATH"
    assert ($err | str contains "ssh-keygen is not on PATH") $"the cause did not survive the cleanup: ($err)"
}

# The README's portability claim, run as a stranger runs it: a bundle arrives,
# and the recipient checks it with no repo, no registered key and no network.
# Every other test here verifies from inside a repo that has been through
# `init`, so none of them can tell a real portability property from a
# dependency on local state that happens to be there.
@test
def "a recipient with no repo of their own can verify a bundle they received" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    # The recipient's whole world: a directory that arrived. No init has run
    # anywhere near it, and `cd` never happens — the command is given a path.
    let received = $tmp_dir | path join received
    cp --recursive $out $received

    let v = verify-bundle $received
    assert $v.valid
    assert $v.signer.bound
    assert equal $v.record $born.record
    assert equal $v.signer.endorsed.status "absent"
}

# The argument is a path typed by hand, so the two ways of getting it wrong
# answer about the ARGUMENT. Without this the first glob inside reports "found
# 0 *.cert.json", which reads as a verdict on a bundle that was never opened.
@test
def "a path that is not a bundle directory is refused as a bad argument" [] {
    let tmp_dir = $in.tmp_dir
    let missing = $tmp_dir | path join nope
    let err = try { verify-bundle $missing; null } catch {|e| $e.msg }
    assert ($err | str contains "no such bundle directory")

    let a_file = $tmp_dir | path join not-a-dir
    "" | save --raw $a_file
    let err2 = try { verify-bundle $a_file; null } catch {|e| $e.msg }
    assert ($err2 | str contains "is not a directory")
}

# The copy helpers raise, but a raise inside an `each` closure is re-wrapped as
# "Eval block failed with pipeline input" and the real message never reaches
# the operator. Three sites were converted to `for` for that reason; the OTS
# copy was missed, and this is the only caller a test can reach it through.
#
# The OTS directory is fabricated rather than stamped: `--no-stamp` everywhere
# in this suite means no calendar server is touched, and `bundle` matches an
# OTS bundle to a root by plain content, so a directory naming the root is all
# discovery needs. The test is about the copy, not about the timestamp.
@test
def "a bundle that could not copy an OTS file names the file" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore

    let mp = $a.home | path join multiproofs
    let root_hex = open --raw ($mp | path join tree-root.txt) | str trim
    let ots = $mp | path join ots-timestamps $"tree-root.($root_hex)"
    mkdir $ots
    open --raw ($mp | path join tree-root.txt) | save --raw ($ots | path join tree-root.txt)
    "proof bytes the export must not silently drop\n" | save --raw ($ots | path join tree-root.txt.ots)
    ^chmod 000 ($ots | path join tree-root.txt.ots)

    let err = try { bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out); null } catch {|e| $e.msg }
    ^chmod 644 ($ots | path join tree-root.txt.ots)
    assert ($err != null) "bundle exported an OTS directory it could not copy"
    assert ($err | str contains "tree-root.txt.ots") $"the refusal does not name the lost file: ($err)"
}

# The repo's signer identity: CID of its single registered (canonical) pubkey.
# `ls`, not `glob`: a test repo path may hold glob metacharacters on purpose.
def signer-cid [home: path]: nothing -> string {
    let pub = ls ($home | path join multiproofs pubkeys)
        | get name
        | where ($it | str ends-with ".pub")
        | first
    open --raw $pub | into binary | cid-v0
}

# What an OpenTimestamps calendar returns from POST /digest: the tail of the
# timestamp chain, here a bare pending attestation naming the public calendar.
#
# Mirrors nu-multiproof's `build-calendar-response` fixture, copied rather than
# imported: that file is another repo's test internals, and `_deps/` shims its
# library modules only. It describes the OTS wire answer, not a format this repo
# owns — and if it ever drifts, upstream's parser rejects it and the test using
# it fails loudly rather than passing on a fixture nobody checks.
def calendar-response []: nothing -> binary {
    let url = "https://a.pool.opentimestamps.org" | into binary
    let len = $url | bytes length
    0x[00]
    | bytes add --end 0x[83dfe30d2ef90c8e]
    | bytes add --end ($len + 1 | into binary --endian little | bytes at 0..0)
    | bytes add --end ($len | into binary --endian little | bytes at 0..0)
    | bytes add --end $url
}

# A Bitcoin-anchored OTS proof over $hash, at block 123456. The other half of
# the calendar fixture above: `--response-file` can only ever produce `pending`,
# because a calendar answers with a pending attestation and confirmation happens
# hours later in a block. So the anchored branch is unreachable from any seal
# this suite can run, and the proof has to be built.
#
# Copied from nu-multiproof's `_ots-fixtures.nu build-bitcoin-ots`, for the same
# reason `calendar-response` is: it describes the OTS wire format, not something
# this repo owns.
#
# Its drift behaviour is NOT the same, though, and the difference matters when
# this test one day fails. A calendar answer goes through `ots stamp`, which
# re-parses what it built and throws. This one is read back by upstream's
# `scan-stamps`, which CATCHES a parse error, prints "note: skipping unparsable
# OTS file" and drops the proof — so drift shows up as a status of `absent`
# where the test wants `anchored`, with the real reason in a note above the
# failure rather than in it.
#
# The height is hardcoded as its varint rather than encoded, because encoding it
# would mean importing upstream's `_varint.nu` — another repo's internals, which
# `_deps/` deliberately does not shim. 123456 -> 0xc0 0xc4 0x07, prefixed by its
# own length; verified against upstream's `encode-varint`.
const OTS_HEADER = 0x[00 4f70656e54696d657374616d7073 0000 50726f6f66 00 bf89e2e884e89294]
const ATT_BITCOIN_TAG = 0x[0588960d73d71901]
const BLOCK_123456 = 0x[03 c0 c4 07]

def bitcoin-ots [hash: binary]: nothing -> binary {
    $OTS_HEADER
    | bytes add --end 0x[01 08]
    | bytes add --end $hash
    | bytes add --end 0x[f1 02 aabb]
    | bytes add --end 0x[08]
    | bytes add --end 0x[00]
    | bytes add --end $ATT_BITCOIN_TAG
    | bytes add --end $BLOCK_123456
}

# An ed25519 keypair whose fingerprint sorts before `ceiling`. Only a key, no
# repo: a co-signer needs nothing but key material and a line in pubkeys/.
# "" = not found yet, the same sentinel shape verify-custody uses for `prev`:
# a `mut` cannot change type, and `loop`+`return` does not satisfy the declared
# return type (the checker reads the loop as producing nothing).
def generate-key-before [tmp_dir: path ceiling: string]: nothing -> record {
    # Capped, because the draw is unbounded: the chance a fresh fingerprint sorts
    # below `ceiling` is ceiling-as-a-fraction-of-the-hex-space, so the attempt
    # count is 1/p — uniform in p, hence divergent in expectation. An author key
    # that sorts very low would keygen for tens of seconds and read as a hang.
    # 200 fails loudly instead, and only for a ceiling under ~1/200 of the space.
    const MAX_TRIES = 200
    mut n = 0
    mut key = ""
    while $key == "" {
        if $n >= $MAX_TRIES {
            error make {msg: $"no ed25519 fingerprint below ($ceiling) in ($MAX_TRIES) tries — the ceiling sorts too low for this test to arrange its ordering"}
        }
        let candidate = $tmp_dir | path join $"cokey-($n)"
        ^ssh-keygen -t ed25519 -f $candidate -N "" -C $"co($n)" -q
        if (open --raw $"($candidate).pub" | pubkey fingerprint) < $ceiling {
            $key = $candidate
        }
        $n = $n + 1
    }
    {key: $key pub: $"($key).pub"}
}

# The three shapes a stamp cell can take, asserted directly on the formatter.
#
# Why not through `verify-bundle`: `stamp-cell`'s result goes to `print`, so an
# end-to-end test reaches the data (the test below does) but never the string.
# And because this function is a deliberate COPY of upstream's `format-stamp`,
# the version upstream pins by test is not the version this repo runs — which is
# exactly how the anchored branch stayed unexecuted while the suite was green.
#
# The shapes are the ones upstream's `pick-stamp` actually emits — it always
# sets `height`, null while unanchored (nu-multiproof `_stamps.nu`), so
# present-but-null is what the `height?` guard is really for. A record with no
# `height` key at all cannot arrive, and asserting on one would pin tolerance
# for input that does not exist.
@test
def "a stamp cell carries the block height when there is one" [] {
    assert equal (stamp-cell {status: "absent" ots: null height: null}) "absent"
    assert equal (stamp-cell {status: "pending" ots: "x.ots" height: null}) "pending"
    assert equal (stamp-cell {status: "anchored" ots: "x.ots" height: 912345}) "anchored 912345"
}

# A sealed, exported bundle carrying one real (pending) stamp, plus the paths
# both stamp tests then work over. Extracted because they set up identically and
# each has to find the same two files by the same rule.
def stamped-bundle [tmp_dir: path]: nothing -> record {
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    let response = $tmp_dir | path join calendar-response.bin
    calendar-response | save --raw --force $response
    seal --repo $a.repo --response-file $response --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    let ots_dir = list-dirs ($out | path join multiproofs ots-timestamps) | first
    let stamps = list-files $ots_dir --suffix ".ots"
    # ONE proof rides in the export, and it is the one over the signature. The
    # root statement is deliberately left undated (`seal.nu` always passes
    # --no-content-anchor), so a reader is never handed two dates and no rule
    # for choosing between them. Asserted here rather than in a caller because
    # `first` below is only meaningful once there is exactly one.
    assert equal ($stamps | length) 1 $"the export carries ($stamps | length) proofs, not just the signature's"
    let stamp = $stamps | first
    # Discovery keys on the stamp's content commitment, so a replacement proof
    # must commit to the sha256 of the file it dates — the SIGNATURE, because
    # this repo anchors the endorsement and never the root statement.
    let sig = $ots_dir | path join ($stamp | path basename | str replace --regex '\.ots$' '.sig')
    assert ($sig | path exists) $"no signature beside the stamp: ($stamp)"
    {signer: $a link: $born out: $out ots_dir: $ots_dir stamp: $stamp sig: $sig}
}

# The anchored data path, end to end. `--response-file` cannot reach it — a
# calendar replies `pending` and confirmation happens later in a block — so the
# proof is built offline and put where discovery finds it. `ots upgrade` is the
# real route to this state and it renames over the same path, so a single
# anchored proof there is what a reader genuinely meets.
@test
def "an endorsement anchored in a block is reported with that block" [] {
    let s = stamped-bundle $in.tmp_dir
    assert equal (verify-bundle $s.out | get signer.endorsed.status) "pending"

    bitcoin-ots (open --raw $s.sig | hash sha256 | decode hex) | save --raw --force $s.stamp
    let after = verify-bundle $s.out
    assert $after.valid "the bundle stopped verifying once its stamp was anchored"
    assert equal $after.signer.endorsed.status "anchored"
    assert equal $after.signer.endorsed.height 123456
    # And the cell the operator reads, over the record this run produced
    assert equal (stamp-cell $after.signer.endorsed) "anchored 123456"

    # What this test also shows, and the reason README calls the block bound the
    # provable one only against a proof you checked yourself: the stamp is not
    # signed and not in the sealed manifest, so the bundle still reports
    # `valid: true` with an attestation no block contains. `verify` is an offline
    # structural check; confirming the block needs upstream's `ots verify`.
    assert not (($s.out | path join multiproofs tree-hashes.csv) | path exists)
}

# The only test in this suite that reaches a REAL stamp through the seal path.
# Everything else seals --no-stamp, so every anchor reads `absent` and is never
# exercised as anything but a missing one.
@test
def "a stamped seal dates the endorsement and anchors nothing else" [] {
    let tmp_dir = $in.tmp_dir
    let s = stamped-bundle $tmp_dir
    let a = $s.signer
    let out = $s.out
    assert ("tree-root.ots" not-in ($s.stamp | path basename)) "the root statement was anchored — --no-content-anchor did not reach upstream"
    # The frozen root copy still ships: bundle.nu finds the OTS directory by
    # matching it against the root hex, so minting must keep writing it.
    assert (($s.ots_dir | path join tree-root.txt) | path exists)

    let v = verify-bundle $out
    assert $v.valid
    # `pending` and not `absent`: the digest reached a calendar. This is the
    # link's date — a link is an assertion by a signer, so the anchor over the
    # signature is the claim, and the record's bytes carry no separate one.
    assert equal $v.signer.endorsed.status "pending"
    assert equal $v.signer.endorsed.signer (open --raw $a.pub | pubkey fingerprint)
    assert ("ots" not-in ($v | columns)) "the content anchor is back in the verify record"
}

@test
def "with a co-signer present, the endorsement reported belongs to the record signer" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    # A second registered key signs the same root statement out of band —
    # upstream dates every signature that verifies, so the bundle now carries
    # two endorsements and only one of them is this record's author.
    #
    # The co-signer's fingerprint must sort BEFORE the author's, or this test
    # does not discriminate: rows arrive in signature-file order, the file name
    # carries the fingerprint, so with the author's key first a positional pick
    # would return the right answer for the wrong reason — about half of runs.
    # ed25519 keygen is milliseconds, so re-rolling the key is the cheap way to
    # fix the order; nothing else about the co-signer needs a repo.
    let a_fp = open --raw $a.pub | pubkey fingerprint
    let co = generate-key-before $tmp_dir $a_fp
    let pubdir = $out | path join multiproofs pubkeys
    let co_fp = open --raw $co.pub | pubkey fingerprint
    open --raw $co.pub | pubkey canonical | save --raw ($pubdir | path join $"($co_fp).pub")
    ssh-sign sign ($out | path join multiproofs tree-root.txt) --key $co.key --pubkeys-dir $pubdir | ignore

    let v = verify-bundle $out
    assert $v.valid
    assert equal ($v.endorsements | get signer | sort) ([$a_fp $co_fp] | sort)
    # Asserted, not assumed: if row order ever stops following the file name,
    # this fails loudly instead of quietly weakening the check below it.
    assert equal ($v.endorsements | first | get signer) $co_fp "the co-signer's row is not first — the check below no longer discriminates"
    # So the correct answer is NOT position 0. The row is chosen by key material
    # through the pubkey table: picking positionally would date the author's
    # link by whenever the co-signer happened to sign.
    assert equal $v.signer.endorsed.signer $a_fp
}

# The case the pick rule exists for: ONE signer holding a stamped signature and
# an unstamped one, where taking the first row reports the wrong answer.
#
# Built with ecdsa because ed25519 signatures are deterministic — re-signing the
# same root reproduces the same bytes, and one key could never hold two different
# valid signatures. The layout is arranged so a positional pick is WRONG:
# `tree-root.txt.<fingerprint>.sig` sorts before `tree-root.txt.sig` (hex digits
# below `s`), so the fingerprint-named file is row 0 and it is the one left
# unstamped, while the bare spelling carries the bytes the stamp covers.
@test
def "an unstamped signature does not hide the signers stamped one" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a" --key-type ecdsa
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    let response = $tmp_dir | path join calendar-response.bin
    calendar-response | save --raw --force $response
    seal --repo $a.repo --response-file $response --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    let mp = $out | path join multiproofs
    let a_fp = open --raw $a.pub | pubkey fingerprint
    let named = $mp | path join $"tree-root.txt.($a_fp).sig"
    # The stamped bytes move to the bare spelling; the fingerprint name gets a
    # fresh signature the existing proof does not cover.
    let stamped = open --raw $named | into binary
    ssh-sign sign ($mp | path join tree-root.txt) --key $a.key --pubkeys-dir ($mp | path join pubkeys) | ignore
    $stamped | save --raw --force ($mp | path join "tree-root.txt.sig")

    let v = verify-bundle $out
    assert $v.valid
    assert equal ($v.endorsements | get signer | uniq) [$a_fp] "the two signatures are not by one key"
    # Both statuses are present, and the WRONG one is first — without that this
    # test would pass against a positional pick and prove nothing.
    assert equal ($v.endorsements | get status) ["absent" "pending"] "the unstamped row is not first — this test no longer discriminates"
    # The signer's endorsement IS dated: a digest reached a calendar for one of
    # their signatures, so reporting `absent` would understate what the bundle
    # proves.
    assert equal $v.signer.endorsed.status "pending"
}

# Two valid signature files by ONE key — the case that makes "a bound signer has
# exactly one endorsement row" false. Both spellings upstream's `sig-files-for`
# discovers are legal in a bundle, and `seal` snapshots both on purpose, so a
# stranger's bundle can carry them without being malformed.
@test
def "two signature spellings by one key do not fork the endorsement" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    let mp = $out | path join multiproofs
    let named = ls $mp | get name | where ($it | str ends-with ".sig") | first
    cp $named ($mp | path join "tree-root.txt.sig")

    let v = verify-bundle $out
    let a_fp = open --raw $a.pub | pubkey fingerprint
    assert $v.valid
    # Two rows, one signer — upstream builds a row per signature FILE
    assert equal ($v.endorsements | length) 2
    assert equal ($v.endorsements | get signer | uniq) [$a_fp]
    # ...and one answer out of them, still the author's
    assert equal $v.signer.endorsed.signer $a_fp
    assert equal $v.signer.endorsed.status "absent"
}

# The receipt half of seal's frozen-proof sweep. A custody receipt freezes under
# the same rule as a birth certificate — the first seal that catalogues it sets
# the earliest provable custody bound — so the same silent break applies: a
# wrong node at the receipt cert path used to read as "already frozen", and the
# receipt then froze under a later root than the seal that first catalogued it.
#
# Lives here and not beside the link case in test_bootstrap.nu because a receipt
# needs a real import to exist, and the import fixtures are here.
@test
def "a wrong node at the receipt cert path is refused like a birth certificate" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let a_out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join a-out)

    let b = make-signer $tmp_dir "b"
    import $a_out --repo $b.repo | ignore
    assert equal (seal --repo $b.repo --no-stamp --allow-untracked-particles | get receipts) 1
    let frozen = $b.home | path join receipts ($born.record.signer) $"($born.edge_cid).receipt.cert.json"
    assert ($frozen | path exists) "the fixture needs a frozen receipt proof"

    # Truncated, as an interrupted write leaves it. The proof is gone but the
    # path is still occupied, which is exactly what bare existence cannot tell.
    "" | save --force --raw $frozen
    let err = try { seal --repo $b.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }
    assert ($err != null) "an empty file passed as a frozen receipt proof"
    assert ($err | str contains $born.edge_cid) $"the refusal should name the receipt: ($err)"

    # And the recovery is removing it — the refusal must not have staged anything
    rm $frozen
    assert equal (seal --repo $b.repo --no-stamp --allow-untracked-particles | get receipts) 1
    assert equal (open $frozen | get leaf.filepath) $"receipts/($born.record.signer)/($born.edge_cid).receipt.json"
}

@test
def "custody chain: each re-export appends a provable, ordered layer" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let a_out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join a-out)

    # B imports the birth bundle: receipt written, first custodian chains to nothing
    let b = make-signer $tmp_dir "b"
    let b_imported = import $a_out --repo $b.repo
    assert equal $b_imported.custody 0
    # import reports the one anchor there is — when the signer endorsed it
    assert ("ots" not-in ($b_imported | columns)) "import is back to reporting a content anchor"
    assert equal $b_imported.endorsed "absent"
    let b_receipt = open --raw $b_imported.receipt | from json
    assert equal $b_receipt.prev null
    assert equal $b_receipt.custodian (signer-cid $b.home)

    # Re-export before sealing must refuse: custody is provable only once sealed
    assert error {|| bundle $born.edge_cid --repo $b.repo --out ($tmp_dir | path join too-early) }

    let sealed_b = seal --repo $b.repo --no-stamp --allow-untracked-particles
    assert equal $sealed_b.receipts 1
    assert (($b.home | path join receipts ($born.record.signer) $"($born.edge_cid).receipt.cert.json") | path exists)
    let b_out = bundle $born.edge_cid --repo $b.repo --out ($tmp_dir | path join b-out)

    # C imports B's re-export: verifies layer 1, chains its own receipt to B's
    let c = make-signer $tmp_dir "c"
    let c_imported = import $b_out --repo $c.repo
    assert equal $c_imported.custody 1
    let c_receipt = open --raw $c_imported.receipt | from json
    let b_layer_receipt = $b_out | path join custody $"1-($b_receipt.custodian | str substring 0..11)" receipts ($born.record.signer) $"($born.edge_cid).receipt.json"
    assert equal $c_receipt.prev (open --raw $b_layer_receipt | hash sha256)

    seal --repo $c.repo --no-stamp --allow-untracked-particles | ignore
    let c_out = bundle $born.edge_cid --repo $c.repo --out ($tmp_dir | path join c-out)

    # A stranger verifies the whole dissemination path offline: A authored,
    # then B held it, then C — ordered by the receipt chain
    let v = verify-bundle $c_out
    assert $v.valid
    assert $v.signer.bound
    assert equal ($v.custody | get index) [1 2]
    assert equal ($v.custody | get custodian) [(signer-cid $b.home) (signer-cid $c.home)]
    assert ($v.custody | all { $in.bound })
    # Every layer dates its own custodian's endorsement, the same way the birth
    # row dates the author's. Without this the chain proved WHO held the link
    # and when the bytes existed, but never when the custodian signed for them.
    assert ($v.custody | all { $in.endorsed != null }) "a custody layer lost its custodian's endorsement"
    assert equal ($v.custody | get endorsed.status) ["absent" "absent"]
    # ...and carries no content anchor either, same rule as the birth row
    assert ($v.custody | all { "ots" not-in ($in | columns) }) "a custody layer is back to carrying a content anchor"

    # ...and the chain survives a fourth hop's import + repo-level verify
    let d = make-signer $tmp_dir "d"
    import $c_out --repo $d.repo | ignore
    let d_check = verify $born.edge_cid --repo $d.repo | first
    assert $d_check.valid
    assert equal ($d_check.custody | length) 2

    # Stripping a middle layer breaks the chain loudly (indices no longer
    # start at 1, and C's prev would point at a missing receipt)
    let stripped = $tmp_dir | path join stripped
    cp --recursive $c_out $stripped
    rm --recursive ($stripped | path join custody $"1-($b_receipt.custodian | str substring 0..11)")
    assert error {|| verify-bundle $stripped }

    # Tampering with a layer's receipt bytes fails its content proof AND the
    # next layer's prev hash — the chain pins every receipt's exact bytes
    let tampered = $tmp_dir | path join tampered
    cp --recursive $c_out $tampered
    let target = $tampered | path join custody $"1-($b_receipt.custodian | str substring 0..11)" receipts ($born.record.signer) $"($born.edge_cid).receipt.json"
    open --raw $target | str replace --regex '"received_at":"\d{4}' '"received_at":"2099' | save --raw --force $target
    let tv = verify-bundle $tampered
    assert not $tv.valid
    assert not ($tv.custody | first | get valid)
}

# Not "handoff: …" because: a leading `word:` makes nutest's generated
# `execute: { <name> }` block parse as a record and the whole suite fails.
@test
def "handoff makes direction a signed claim, woven into the custody chain" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let b = make-signer $tmp_dir "b"
    let c = make-signer $tmp_dir "c"

    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore

    # A hands the birth bundle to B by signer CID: signed handoff at the root
    let a_out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join a-out) --to (signer-cid $b.home)
    let root_handoff = $a_out | path join $"($born.edge_cid).handoff.json"
    assert ($root_handoff | path exists)
    let av = verify-bundle $a_out
    assert $av.valid
    assert equal $av.handed_to (signer-cid $b.home)

    # Wrong recipient: mallory can hold the bundle but cannot become a custodian
    let m = make-signer $tmp_dir "m"
    assert error {|| import $a_out --repo $m.repo }

    # Pinned residual (accepted, README "Three honest limits"): the refusal
    # above is a fail-fast for honest flows, not a boundary — whoever holds
    # the bytes can strip the unsealed handoff and import the bundle as an
    # open one. Only the recipient's SEAL makes a handoff permanent (the
    # strip-after-seal case is caught, tested at the end of this test).
    let laundered = $tmp_dir | path join laundered
    cp --recursive $a_out $laundered
    rm ($laundered | path join $"($born.edge_cid).handoff.json")
    glob ($laundered | path join $"($born.edge_cid).handoff.json.*.sig") | each {|f| rm $f }
    let m_imported = import $laundered --repo $m.repo

    # Forged custodian at the custody level: mallory edits their receipt to
    # claim B's identity before sealing. The seal signs the forged bytes fine —
    # only the binding check (custodian CID vs the validly-signing key) refuses.
    open --raw $m_imported.receipt
    | str replace (signer-cid $m.home) (signer-cid $b.home)
    | save --raw --force $m_imported.receipt
    seal --repo $m.repo --no-stamp --allow-untracked-particles | ignore
    let m_out = bundle $born.edge_cid --repo $m.repo --out ($tmp_dir | path join m-out)
    let mv = verify-bundle $m_out
    assert not $mv.valid
    assert not ($mv.custody | first | get bound)

    # The named recipient imports; the receipt pins the handoff's hash
    let b_imported = import $a_out --repo $b.repo
    let b_receipt = open --raw $b_imported.receipt | from json
    assert equal $b_receipt.handoff (open --raw $root_handoff | hash sha256)

    seal --repo $b.repo --no-stamp --allow-untracked-particles | ignore
    let b_out = bundle $born.edge_cid --repo $b.repo --out ($tmp_dir | path join b-out) --to (signer-cid $c.home)

    import $b_out --repo $c.repo | ignore
    seal --repo $c.repo --no-stamp --allow-untracked-particles | ignore
    # C re-exports openly (no recipient): legal, the chain just ends unaddressed
    let c_out = bundle $born.edge_cid --repo $c.repo --out ($tmp_dir | path join c-out)

    let v = verify-bundle $c_out
    assert $v.valid
    assert equal $v.handoff.to (signer-cid $b.home)
    assert equal ($v.custody | first | get handoff | get to) (signer-cid $c.home)
    assert equal ($v.custody | last | get handoff) null
    assert equal $v.handed_to null

    # Stripping the author's handoff breaks B's sealed receipt — detected
    let stripped = $tmp_dir | path join stripped
    cp --recursive $c_out $stripped
    rm ($stripped | path join $"($born.edge_cid).handoff.json")
    glob ($stripped | path join $"($born.edge_cid).handoff.json.*.sig") | each {|f| rm $f }
    assert not (verify-bundle $stripped | get valid)
}

@test
def "forged authorship is refused: signer CID of a key that never signed" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"

    # The record claims key-mallory's identity, but the seal is signed by a's key
    let mallory = $tmp_dir | path join key-mallory
    ^ssh-keygen -t ed25519 -f $mallory -N "" -C mallory -q
    let mallory_cid = open --raw $"($mallory).pub" | into binary | cid-v0
    let born = link add $P1 $P2 --repo $a.repo --signer $mallory_cid --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore

    let bundle_dir = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out-bundle)
    let v = verify-bundle $bundle_dir
    assert $v.structure_valid
    assert not $v.signer.bound
    assert not $v.valid

    let b = make-signer $tmp_dir "b"
    assert error {|| import $bundle_dir --repo $b.repo }
}

# A bundle chooses its own file names, and nothing else about it. The binding
# must therefore ask key material both times: which key signed (the verdict
# row's principal, a fingerprint since nu-multiproof b6d7b11) and which key the
# claimed signer CID addresses. Matching the principal against a pubkey file's
# STEM put a name back in the trust path — this is that attack, end to end.
#
# No apostrophe in the name: nutest builds `execute: { <name> }`, so a `'` in
# it opens a string the generated block never closes and the whole suite fails
# to parse (same trap as the leading `word:` noted above).
@test
def "a pubkey filed under the fingerprint of another key cannot borrow its authorship" [] {
    let tmp_dir = $in.tmp_dir
    let m = make-signer $tmp_dir "mallory"
    let victim = make-signer $tmp_dir "victim"
    let victim_canon = open --raw $victim.pub | pubkey canonical
    let victim_cid = $victim_canon | into binary | cid-v0

    # mallory claims the victim authored the link, and seals with her own key
    let born = link add $P1 $P2 --repo $m.repo --signer $victim_cid --allow-missing
    seal --repo $m.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $m.repo --out ($tmp_dir | path join out)
    assert not (verify-bundle $out | get signer.bound) "unforged bundle already bound"

    # The forgery: mallory's key moves to a name nothing reads, and the
    # victim's key takes the file name that IS mallory's principal. The trust
    # list renders from key material, so mallory's signature still validates.
    let pubdir = $out | path join multiproofs pubkeys
    let mallory_fp = open --raw $m.pub | pubkey fingerprint
    mv ($pubdir | path join $"($mallory_fp).pub") ($pubdir | path join "decoration.pub")
    $victim_canon | save --raw --force ($pubdir | path join $"($mallory_fp).pub")

    let v = verify-bundle $out
    assert equal ($v.signatures | where valid | get signer) [$mallory_fp]
    assert not $v.signer.bound "the victim's signer CID was bound to mallory's signature"
    # And no endorsement date either, though the bundle carries one: mallory's
    # signature is valid, so upstream lists it in `endorsements`. Reporting that
    # row as the victim's would date an endorsement the victim never made.
    assert equal ($v.endorsements | get signer) [$mallory_fp]
    assert equal $v.signer.endorsed null "an unbound signer was handed someone else's endorsement"
    assert not $v.valid
    let c = make-signer $tmp_dir "carol"
    assert error {|| import $out --repo $c.repo }
}

# A repo path is data, never a pattern. Every discovery site used to splice it
# into a glob, so one `[` above the graph made the whole module silently see an
# empty repo: `seal`'s pre-seal self-addressing sweep validated no record at
# all, and verification found no pubkey, no certificate and no imported copy.
# Silence is what makes it dangerous — nothing errors, the answers just go
# empty. The metacharacters here are the ones nushell's glob reads.
@test
def "a repo path holding glob metacharacters still seals, exports and imports" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a[v1]{x}"
    let b = make-signer $tmp_dir "b?[2]"

    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    let sealed = seal --repo $a.repo --no-stamp --allow-untracked-particles
    assert equal $sealed.newborn 1
    # `ls`, not `glob`: the assertion must not repeat the bug it is pinning
    assert equal (ls $sealed.snapshot | get name | where ($it | str ends-with ".sig") | length) 1

    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out) --to (signer-cid $b.home)
    assert (verify $born.edge_cid --repo $a.repo | first | get valid)

    let imported = import $out --repo $b.repo
    assert (verify $born.edge_cid --repo $b.repo | first | get valid)
    # ...and the receipt's file manifest is the bundle, not an empty list
    assert ((open --raw $imported.receipt | from json | get files | length) > 0)
}

# A pubkey file's name is decoration upstream — `mv` is how an operator sets
# it, and a key registered under any name still signs and verifies. Export must
# therefore find the signer's key by fingerprint, not by joining the sig name
# onto pubkeys/. The signer CID is the file BYTES, so a rename changes nothing
# the bundle claims.
@test
def "a renamed pubkey file still exports a verifiable bundle" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let pubkeys = $a.home | path join multiproofs pubkeys
    mv (glob ($pubkeys | path join *.pub) | first) ($pubkeys | path join "my-laptop.pub")

    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let v = verify-bundle (bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out))
    assert $v.valid
    assert $v.signer.bound
}

@test
def "non-canonical pubkey file in a bundle is refused" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let bundle_dir = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out-bundle)

    # Re-adding a comment keeps the key material — the signature would still
    # verify and the signer would merely unbind. The canonical-form check must
    # refuse the bundle outright instead, naming the malformed file.
    let pub = glob ($bundle_dir | path join multiproofs pubkeys *.pub) | first
    let raw = open --raw $pub | str trim
    $"($raw) mallory\n" | save --raw --force $pub
    assert error {|| verify-bundle $bundle_dir }
}

# Signer identity is the CID of the file BYTES, so the canonical check must be
# a byte check. A UTF-8 BOM is the case that proves it: nushell's `decode`
# strips one, so the decoded string compares equal to the canonical form while
# the bytes — and therefore the CID — differ. That is the one-key-two-identities
# fork the canonical form exists to close.
@test
def "a pubkey file with a byte-order mark is not the canonical form" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let bundle_dir = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out-bundle)

    let pub = glob ($bundle_dir | path join multiproofs pubkeys *.pub) | first
    let canon = open --raw $pub | into binary
    ((0x[EF BB BF]) ++ $canon) | save --raw --force $pub
    assert equal (open --raw $pub | into binary | decode) ($canon | decode)
    assert not ((open --raw $pub | into binary | cid-v0) == ($canon | cid-v0))
    assert error {|| verify-bundle $bundle_dir }
}

# `pubkey canonical` shells out to OpenSSH, so it throws for reasons that are
# not about the key at all. The refusal must say which — a bare `try {}` turned
# a missing ssh-keygen into "non-canonical pubkey file" over a good ed25519
# key, the verdict-about-the-key mistake nu-multiproof 310c29b exists to avoid.
@test
def "a broken toolchain is refused as a toolchain problem, not as a bad key" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    let err = with-env {PATH: []} {
        try { verify-bundle $out | ignore; null } catch {|e| $e.msg }
    }
    assert ($err != null) "a bundle verified with no ssh-keygen on PATH"
    assert ($err | str contains "toolchain problem") $"the refusal blamed the key: ($err)"
    # Containing the right tail is not enough — the wrapper used to PREFIX it
    # with a verdict of its own ("… is not an SSH public key: …"), so one
    # sentence asserted what its own ending denied. Asserted as a property, not
    # as this repo's wording: the wrapper must supply the file name and no verb.
    assert ($err | str contains ($out | path join multiproofs pubkeys)) $"the refusal does not name the file: ($err)"
    assert not ($err | str contains "is not an SSH public key") $"the wrapper decided about the key before upstream did: ($err)"
}

# The other throw out of `pubkey canonical`, and the reason the wrapper adds no
# verb at all. This vector is a padded copy of a real RSA key (upstream's
# RSA_PADDED_MODULUS): OpenSSH LOADS it and fingerprints it identically, then
# re-encodes it differently — so "cannot read this as a key" would be as wrong
# here as "is not an SSH public key" was on the missing-toolchain branch. One
# wrapper serves both only by staying silent about what happened.
const RSA_PADDED_MODULUS = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAgAAxMZ8FFYbCIeusNTiBhxcq9Ka4qJ8R6BxJpEnYA7zKPOrw2qx8DvPB+ckOGYUXFEwUuKS2DGxjHhkHx0AWySOD/F2q7IMrO03zGfaCau/7b0p7fOcX5F4sYUkkzJpdw/NBQL4UuIT450m6mmlXgXFund7ggxqYm12fXrXnfZ2NT7FbbLxE+e6KCfKhoeHt5apMAlyWgihgGOM6rU2SgBI7JtD3ArnhQ7jfc1k082MvV2bnKnBmgQ7Ja8pYseQFvNUMDs1pZBO57pFhgoLki1Hs5rPMq9TVPWdhwZcLd4VQuQS6jzqw1keeY4RELhlfEVWQU+i2lX1XT6oTQNZSU5/Yw=="

@test
def "a second encoding of a real key is refused without calling it unreadable" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    let pub = glob ($out | path join multiproofs pubkeys *.pub) | first
    $"($RSA_PADDED_MODULUS)\n" | save --raw --force $pub

    let err = try { verify-bundle $out | ignore; null } catch {|e| $e.msg }
    assert ($err != null) "a bundle carrying a second encoding of a key verified"
    assert ($err | str contains "not the encoding OpenSSH writes") $"upstream's verdict was replaced: ($err)"
    assert ($err | str contains $pub) $"the refusal does not name the file: ($err)"
    # The whole point: OpenSSH read this key. A message saying otherwise would
    # send the operator after a corrupt file that is not corrupt.
    assert not ($err | str contains "cannot read") $"the refusal calls a readable key unreadable: ($err)"
}

@test
def "tampered record in a bundle fails self-addressing" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let bundle_dir = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out-bundle)

    let rec_file = $bundle_dir | path join $born.record.signer $"($born.edge_cid).json"
    open --raw $rec_file | str replace $P2 $P1 | save --raw --force $rec_file
    assert error {|| verify-bundle $bundle_dir }
}

const FAKE_SHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

# check-handoff's two defense paths, at the bundle root and in a custody
# layer: the claims must match the link/holder/receipt the file travels
# with, and the bytes must carry a valid signature by the `from` signer.
# Each scenario tampers exactly one thing on a fresh copy; the asserted
# error fragment pins WHICH check fired, not its wording.
@test
def "a handoff that is tampered, unsigned, or misclaiming is refused" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let b = make-signer $tmp_dir "b"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let a_out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join a-out) --to (signer-cid $b.home)
    let handoff_name = $"($born.edge_cid).handoff.json"

    # Tampered signed bytes: the claims stay coherent (handed_at is not a
    # checked claim), only the signature no longer covers the file
    let bad_sig = $tmp_dir | path join bad-sig
    cp --recursive $a_out $bad_sig
    let f = $bad_sig | path join $handoff_name
    open --raw $f | str replace --regex '"handed_at":"\d{4}' '"handed_at":"2099' | save --raw --force $f
    let v = verify-bundle $bad_sig
    assert not $v.valid
    assert not $v.handoff.valid
    assert ($v.error | str contains "no valid signature")
    # a handoff that fails verification must not name an addressee
    assert equal $v.handed_to null
    assert error {|| import $bad_sig --repo $b.repo }

    # Signature stripped but the handoff kept: a claim without proof. Nothing
    # legitimate produces a handoff with no signature beside it, so this is a
    # malformed bundle and must THROW naming the file — not come back as
    # "no valid signature by the handoff's `from` signer", which is a verdict
    # about a signature that was never there to weigh.
    let no_sig = $tmp_dir | path join no-sig
    cp --recursive $a_out $no_sig
    glob ($no_sig | path join $"($handoff_name).*.sig") | each {|s| rm $s }
    let e2 = try { verify-bundle $no_sig | ignore; null } catch {|e| $e.msg }
    assert ($e2 != null and ($e2 | str contains "no signature files found")) $"unsigned handoff did not throw: ($e2)"
    assert ($e2 | str contains $handoff_name)

    # `from` claims an identity other than the holder it travels with
    let wrong_from = $tmp_dir | path join wrong-from
    cp --recursive $a_out $wrong_from
    let f3 = $wrong_from | path join $handoff_name
    open --raw $f3 | str replace $born.record.signer $P1 | save --raw --force $f3
    let v3 = verify-bundle $wrong_from
    assert not $v3.valid
    assert ($v3.error | str contains "handoff claims do not match")

    # The author's handoff must pin receipt null — a non-null hash mismatches
    let wrong_receipt = $tmp_dir | path join wrong-receipt
    cp --recursive $a_out $wrong_receipt
    let f4 = $wrong_receipt | path join $handoff_name
    open --raw $f4 | str replace '"receipt":null' $'"receipt":"($FAKE_SHA)"' | save --raw --force $f4
    let v4 = verify-bundle $wrong_receipt
    assert not $v4.valid
    assert ($v4.error | str contains "handoff claims do not match")

    # Same checks on a custody layer's outgoing handoff: B imports, seals,
    # re-exports handed to C — then the layer handoff's `receipt` is edited
    # to a hash that is not B's receipt
    let c = make-signer $tmp_dir "c"
    import $a_out --repo $b.repo | ignore
    seal --repo $b.repo --no-stamp --allow-untracked-particles | ignore
    let b_out = bundle $born.edge_cid --repo $b.repo --out ($tmp_dir | path join b-out) --to (signer-cid $c.home)
    assert (verify-bundle $b_out | get valid)

    let wrong_layer = $tmp_dir | path join wrong-layer
    cp --recursive $b_out $wrong_layer
    let lf = $wrong_layer | path join custody $"1-(signer-cid $b.home | str substring 0..11)" $handoff_name
    open --raw $lf | str replace --regex '"receipt":"[0-9a-f]{64}"' $'"receipt":"($FAKE_SHA)"' | save --raw --force $lf
    let lv = verify-bundle $wrong_layer
    assert not $lv.valid
    assert not ($lv.custody | first | get handoff | get valid)
    assert ($lv.error | str contains "handoff claims do not match")
    assert equal $lv.handed_to null
}

# The layer dirname is transport only — verification must refuse whenever
# the name and the verified receipt disagree, however the name was forged.
@test
def "custody layer names cannot lie — forged dirname, duplicated custodian, renumbered index" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let a_out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join a-out)
    let b = make-signer $tmp_dir "b"
    import $a_out --repo $b.repo | ignore
    seal --repo $b.repo --no-stamp --allow-untracked-particles | ignore
    let b_out = bundle $born.edge_cid --repo $b.repo --out ($tmp_dir | path join b-out)
    let a12 = signer-cid $a.home | str substring 0..11
    let b12 = signer-cid $b.home | str substring 0..11

    # Well-formed dirname claiming another signer: dirname-vs-receipt throw
    let forged = $tmp_dir | path join forged
    cp --recursive $b_out $forged
    mv ($forged | path join custody $"1-($b12)") ($forged | path join custody $"1-($a12)")
    let err = try { verify-bundle $forged | ignore; null } catch {|e| $e.msg }
    assert ($err != null and ($err | str contains "does not match its receipt's custodian"))

    # Same custodian twice: layer 2 is a byte-copy of layer 1, so its name
    # and binding check out — its receipt chains to nothing while the chain
    # demands layer 1's hash. Refused by `prev`, not by naming.
    let dup = $tmp_dir | path join dup
    cp --recursive $b_out $dup
    cp --recursive ($dup | path join custody $"1-($b12)") ($dup | path join custody $"2-($b12)")
    let v = verify-bundle $dup
    assert not $v.valid
    assert ($v.custody | first | get valid)
    assert (($v.custody | last | get error) | str contains "prev hash does not match")

    # Renumbering the only layer: indices must be contiguous from 1 — this
    # pins the non-strip contiguity case (the middle-strip case is covered
    # in the custody chain test above)
    let renum = $tmp_dir | path join renum
    cp --recursive $b_out $renum
    mv ($renum | path join custody $"1-($b12)") ($renum | path join custody $"2-($b12)")
    let err2 = try { verify-bundle $renum | ignore; null } catch {|e| $e.msg }
    assert ($err2 != null and ($err2 | str contains "not contiguous"))
}

# The signing key resolves before the destination dir is created: a key error
# after assembly used to leave a complete-looking bundle whose handoff was
# unsigned, and the retry with --key was blocked by "destination already exists".
@test
def "bundle --to without a signing key fails before writing anything" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore

    ^git -C $a.repo config --unset user.signingKey
    let dest = $tmp_dir | path join out
    assert error {|| bundle $born.edge_cid --repo $a.repo --out $dest --to $P1 }
    assert not ($dest | path exists)

    # ...so the retry with an explicit --key finds the destination free
    let out = bundle $born.edge_cid --repo $a.repo --out $dest --to $P1 --key $a.key
    assert (($out | path join $"($born.edge_cid).handoff.json") | path exists)
    assert ((glob ($out | path join $"($born.edge_cid).handoff.json.*.sig") | length) == 1)
}

# The writer's exit self-check: whatever breaks assembly (the observed case
# was an interior `cp -r` error printed but not raised), a bundle without its
# root certificate must error and be removed, not ship with exit 0.
@test
def "a re-export that comes out without a root certificate is refused and removed" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let a_out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join a-out)
    let b = make-signer $tmp_dir "b"
    import $a_out --repo $b.repo | ignore
    seal --repo $b.repo --no-stamp --allow-untracked-particles | ignore

    # Corrupt the source copy so assembly produces a certless bundle root
    rm ($b.home | path join imported $born.record.signer $born.edge_cid $"($born.edge_cid).cert.json")
    let dest = $tmp_dir | path join b-out
    let err = try { bundle $born.edge_cid --repo $b.repo --out $dest | ignore; null } catch {|e| $e.msg }
    assert ($err != null and ($err | str contains "incomplete"))
    assert not ($dest | path exists)
}

# The same rule one layer over: what makes a key usable is upstream's to
# decide, and it narrowed (nu-multiproof b6d7b11 — `ssh-sign sign` now always
# demands the key be registered). A local pre-check that only asked "does the
# file exist" therefore let assembly finish, and the refusal landed after the
# handoff was written: a complete-looking bundle with an unsigned handoff, and
# a retry blocked by "bundle destination already exists".
@test
def "an export whose handoff key upstream refuses leaves nothing behind" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let b = make-signer $tmp_dir "b"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore

    # A real key with its .pub sibling, absent from pubkeys/ — nothing local
    # can fault it, so only `ssh-sign sign` refuses, at the very last step.
    let stranger = $tmp_dir | path join key-stranger
    ^ssh-keygen -t ed25519 -f $stranger -N "" -C stranger -q

    let dest = $tmp_dir | path join out
    let err = try {
        bundle $born.edge_cid --repo $a.repo --out $dest --to (signer-cid $b.home) --key $stranger | ignore
        null
    } catch {|e| $e.msg }
    assert ($err != null and ($err | str contains "not registered")) $"unregistered handoff key did not throw: ($err)"
    assert not ($dest | path exists)

    # ...so the retry with the registered key finds no debris in its way
    let out = bundle $born.edge_cid --repo $a.repo --out $dest --to (signer-cid $b.home) --key $a.key
    assert (($out | path join $"($born.edge_cid).handoff.json") | path exists)
}

# `link list`/`touching`/`tally` stay own-graph-only on purpose — `link
# imported` is the companion reader gm-vote (bostrom-journal) had to build by
# hand outside the module (consensus.nu: import every bundle, then decode
# imported/ itself). Two signers, two different edge shapes: a plain edge
# (no instruction source, `op` stays null) and a convention edge (`op`
# decodes from the instruction record `bundle` now attaches by default).
@test
def "link imported decodes every landed bundle, across signers" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let b = make-signer $tmp_dir "b"
    let c = make-signer $tmp_dir "c"

    let aq = convention question $P1 "why?" --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let a_out = bundle $aq.edge_cid --repo $a.repo --out ($tmp_dir | path join a-out)

    let bp = link add "cyber" "bostrom" --repo $b.repo
    seal --repo $b.repo --no-stamp --allow-untracked-particles | ignore
    let b_out = bundle $bp.edge_cid --repo $b.repo --out ($tmp_dir | path join b-out)

    import $a_out --repo $c.repo | ignore
    import $b_out --repo $c.repo | ignore

    let rows = link imported --repo $c.repo
    assert equal ($rows | length) 2
    # Own graph stays untouched by the import — the boundary `list` draws
    assert equal (link list --repo $c.repo | length) 0

    let a_row = $rows | where edge_cid == $aq.edge_cid | first
    assert equal $a_row.signer (signer-cid $a.home)
    assert equal $a_row.cid_from $aq.record.cid_from
    assert equal $a_row.op "question"
    assert equal $a_row.src {about: $P1, op: "question"}

    let b_row = $rows | where edge_cid == $bp.edge_cid | first
    assert equal $b_row.signer (signer-cid $b.home)
    assert equal $b_row.op null "a plain edge's cid_from is not an instruction — op must stay null"
}

# Confirms the reason `link imported` builds a per-bundle store index instead
# of reaching into this repo's own particles/: two signers can each publish a
# question about the SAME file, and the two instruction records are then
# distinct particles (different `about`) even though they decode to the same
# shape once dereferenced — nothing about reading one bundle should touch
# the other's particles, or the identity of a repo's own store either.
@test
def "link imported never reaches into this own repo particles" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let c = make-signer $tmp_dir "c"

    let aq = convention question $P1 "why?" --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let a_out = bundle $aq.edge_cid --repo $a.repo --out ($tmp_dir | path join a-out) --links-only
    import $a_out --repo $c.repo | ignore

    # links-only: the bundle carries no particles/ at all. c independently
    # publishes the EXACT instruction record bytes (not just any content) —
    # same CID as $aq.record.cid_from — so a reader that fell back to this
    # repo's own store would dereference it and this test would catch that;
    # only a reader scoped to the bundle's own particles/ stays null.
    record-bytes {about: $P1, op: "question"} | particle add --repo $c.repo | ignore
    let rows = link imported --repo $c.repo
    assert equal ($rows | length) 1
    assert equal ($rows | first | get op) null "a links-only bundle has no preimage to dereference, even though this repo happens to independently hold the same instruction record"
}

# The routine two-holder state: B imported A's bundle of an edge, then
# asserted the same pair itself with `link add`. Between that add and B's
# next seal, plain `verify <edge>` used to raise "no birth certificate yet"
# from inside the own-copies loop — before imported copies were even
# collected — so a copy that verified a moment ago became unreachable except
# via --signer. The pending own copy must not cost the imported rows.
@test
def "an unsealed own copy does not hide a verifiable imported copy" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    let b = make-signer $tmp_dir "b"
    import $out --repo $b.repo | ignore
    assert equal (verify $born.edge_cid --repo $b.repo | length) 1

    # B asserts the same pair; its own copy now exists with no certificate.
    link add $P1 $P2 --repo $b.repo --allow-missing | ignore
    let rows = verify $born.edge_cid --repo $b.repo
    assert equal ($rows | length) 1 "the pending own copy must be set aside, not abort the query"
    assert ($rows | first | get valid)
    assert equal ($rows | first | get record.signer) $born.record.signer

    # When the pending copy is ALL there is, the old refusal still stands —
    # pointing at seal, not at "unknown edge".
    let second = link add $P2 $P1 --repo $b.repo --allow-missing
    let err = try { verify $second.edge_cid --repo $b.repo; null } catch {|e| $e.msg }
    assert ($err | str contains "no birth certificate yet") $"wrong refusal for an edge held only unsealed: ($err)"

    # After B's seal the same query returns both copies.
    seal --repo $b.repo --no-stamp --allow-untracked-particles | ignore
    assert equal (verify $born.edge_cid --repo $b.repo | length) 2
}

# Import takes custody of an act; it does not speak about one. So the link CID
# it returns is derived and its preimage is not written here — the custodian's
# store gains a file when the custodian names the cyberlink, not when the bytes
# arrive. The previous behaviour minted it, on a reason that had already
# expired (the sealed receipt states the act's components now, so nothing here
# needed that CID dereferenced).
@test
def "import derives the link CID it returns and publishes no preimage for it" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)

    let b = make-signer $tmp_dir "b"
    let landed = import $out --repo $b.repo
    assert equal $landed.link ((record-bytes $born.record) | cid-v0)
    assert not (($b.home | path join particles $landed.link) | path exists)

    # And the custodian can still publish it deliberately, to say something
    # about the cyberlink it now holds. --allow-missing because the endpoints'
    # bytes are in the read-only imported copy, not in this repo's own store:
    # the one case the flag exists for, a reference to bytes held elsewhere.
    assert equal (particle add-link $born.record.cid_from $born.record.cid_to $born.record.signer --repo $b.repo --allow-missing) $landed.link
}

# The layout's whole point: one edge filename may exist under several signer
# directories, and verify's contract is one row per own signer directory —
# per-signer certs, per-signer credit. Never pinned sealed: the only
# multi-signer fixture ran read-only `link touching`. Also the first coverage
# of `--signer` on repo-level verify: a filter bug (matching the wrong field,
# or the full path instead of the basename) would return every copy or
# refuse a signer that holds the edge, and the suite stayed green.
@test
def "verify returns one row per own signer and --signer narrows to one act" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let own = link add $P1 $P2 --repo $a.repo --allow-missing
    let adhoc = link add $P1 $P2 --repo $a.repo --allow-missing --signer alice
    assert equal $own.edge_cid $adhoc.edge_cid "one pair, one edge address, whoever signs"
    let sealed = seal --repo $a.repo --no-stamp --allow-untracked-particles
    assert equal $sealed.newborn 2
    assert (($a.home | path join certs $adhoc.record.signer $"($adhoc.edge_cid).cert.json") | path exists) "certs must mirror the second signer directory too"

    let rows = verify $own.edge_cid --repo $a.repo
    assert equal ($rows | get record.signer | sort) ([$own.record.signer $adhoc.record.signer] | sort)
    # Credit is per signer: the repo's key endorsed the seal, so the
    # registered signer's copy binds; the ad-hoc signer never signed
    # anything, and its row must say so rather than borrow the repo's
    # signature.
    assert ($rows | where record.signer == $own.record.signer | first | get signer.bound)
    assert not ($rows | where record.signer == $adhoc.record.signer | first | get signer.bound)

    let narrowed = verify $own.edge_cid --repo $a.repo --signer $adhoc.record.signer
    assert equal ($narrowed | length) 1
    assert equal ($narrowed | first | get record.signer) $adhoc.record.signer

    let err = try { verify $own.edge_cid --repo $a.repo --signer $P1; null } catch {|e| $e.msg }
    assert ($err | str contains "unknown edge") $"a signer holding no copy must read as unknown, got: ($err)"
}

# CLAUDE.md's invariant: receipt paths mirror the edge layout, and the
# receipt itself STATES the act — cid_from, cid_to, signer — rather than
# addressing it. Pinned two ways, because the writer (import) and the checker
# (custody verification) share their helpers: the raw bytes against a
# hand-spelled prefix, and the recovered address against a hand-spelled
# canonical triple. Before the fields were spelled out this held one derived
# CID, and flipping it to the edge CID — the natural slip of an edge-first
# refactoring — kept every test green.
@test
def "the receipt states the act and still derives to the cyberlink CID" [] {
    let tmp_dir = $in.tmp_dir
    let a = make-signer $tmp_dir "a"
    let born = link add $P1 $P2 --repo $a.repo --allow-missing
    seal --repo $a.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $a.repo --out ($tmp_dir | path join out)
    let b = make-signer $tmp_dir "b"
    import $out --repo $b.repo | ignore

    let raw = open --raw ($b.home | path join receipts $born.record.signer $"($born.edge_cid).receipt.json")
    let receipt = $raw | from json
    let signer = $born.record.signer
    assert equal ($receipt | select cid_from cid_to signer) {cid_from: $P1, cid_to: $P2, signer: $signer}
    assert ("link" not-in ($receipt | columns)) "the receipt must state the act, not address it"
    # Key order is the byte format: the act first, then who took it.
    assert ($raw | str starts-with $"{\"cid_from\":\"($P1)\",\"cid_to\":\"($P2)\",\"signer\":\"($signer)\",\"custodian\":")

    # The address stays recoverable from the receipt's own bytes — that is what
    # spelling the components out buys, with no store to consult.
    let triple_cid = $"{\"cid_from\":\"($P1)\",\"cid_to\":\"($P2)\",\"signer\":\"($signer)\"}\n"
        | into binary | cid-v0
    assert equal (record-bytes ($receipt | select cid_from cid_to signer) | cid-v0) $triple_cid
}
