# The position — a link's place in its signer's run, in its two states.
#
# `link add` writes the time the act arrived; the seal turns that time into a
# number. What the number buys is provable completeness: a run with no gaps is
# what makes a withheld link visible, so the tests here are mostly refusals.
# The seal is where they live, because that is the moment a position stops
# being a claim on disk and becomes something a stranger can check.
#
# Every seal here passes --allow-untracked-particles, for the reason the other
# suites give: none of these tests is about the store's commit discipline, and
# they never commit anything.
use std/assert
use std/testing *

use ../nu-cybergraph/init.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/order.nu
use ../nu-cybergraph/seal.nu
use ../nu-cybergraph/bundle.nu
use ../nu-cybergraph/verify.nu
use ../nu-cybergraph/verify-bundle.nu
use ../nu-cybergraph/_layout.nu [ order-dir order-path order-cert-path order-relpath cert-path certs-dir link-path snapshot-dir ]
use ../nu-cybergraph/_order.nu [ write-added-at read-position ]
use ../nu-cybergraph/_record.nu [ edge-bytes edge-cid ]
use ../nu-cybergraph/_validate.nu [ RFC3339_UTC_RE ]

const P1 = "QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF"
const P2 = "QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"
const P3 = "QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV"

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

def make-signer [tmp_dir: path]: nothing -> record {
    let repo = $tmp_dir | path join repo

    mkdir $repo
    ^git init --object-format=sha256 -q $repo
    ^git -C $repo config user.name t
    ^git -C $repo config user.email t@t
    let key = $tmp_dir | path join key

    ^ssh-keygen -t ed25519 -f $key -N "" -q
    ^git -C $repo config user.signingKey $key
    init --repo $repo
    {repo: $repo home: ($repo | path join cybergraph) key: $key}
}

# The number a position states, as an int — the reading every assertion below
# makes, so none of them has to spell out that `seq` is a string on disk.
def seq-of [file: path]: nothing -> int {
    read-position $file | get seq | into int
}

# --- what `link add` writes ---

@test
def "link add stamps each act with the time it arrived" [] {
    let s = make-signer $in.tmp_dir
    let first = link add $P1 $P2 --repo $s.repo --allow-missing
    let second = link add $P1 $P3 --repo $s.repo --allow-missing

    let stamps = [$first $second] | each {|l|
        let file = order-path $s.home $l.record.signer $l.edge_cid

        assert ($file | path exists) $"no position beside ($l.edge_cid)"
        read-position $file | get added_at
    }

    for at in $stamps { assert ($at =~ $RFC3339_UTC_RE) $"stamped ($at)" }
    assert ((($stamps | first) | into datetime) <= (($stamps | last) | into datetime))
}

# `link add` reports the act, never its place in the run. No number, because
# none exists until a seal numbers it; and no time either, because the claimed
# time is scaffolding the seal deletes — a column for it would answer null on
# a repeat of an already-sealed act. The run is read by `order list`.
@test
def "link add reports the act and not its place in the run" [] {
    let s = make-signer $in.tmp_dir

    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    assert equal ($born | columns) [edge_cid path record]
    assert equal (read-position (order-path $s.home $born.record.signer $born.edge_cid) | columns) [added_at]
}

# The triple guard covers both files: one act, one address, one record, one
# position. A second position for the same act would be a second act.
@test
def "a repeat writes no second position and leaves the first alone" [] {
    let s = make-signer $in.tmp_dir
    let first = link add $P1 $P2 --repo $s.repo --allow-missing
    let file = order-path $s.home $first.record.signer $first.edge_cid
    let stamped = open --raw $file

    link add $P1 $P2 --repo $s.repo --allow-missing | ignore

    assert equal (open --raw $file) $stamped "a repeat restamped the act"
    assert equal (ls (order-dir $s.home | path join $first.record.signer) | length) 1
}

# The run is per signer directory, so the light --signer workflow has its own
# sequence and cannot collide with the identity's — each numbered from 0.
@test
def "each signer directory carries its own run" [] {
    let s = make-signer $in.tmp_dir
    let mine = link add $P1 $P2 --repo $s.repo --allow-missing
    let adhoc = link add $P1 $P2 --repo $s.repo --allow-missing --keyless-signer alice

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore

    assert not equal $mine.record.signer $adhoc.record.signer
    assert equal (seq-of (order-path $s.home $mine.record.signer $mine.edge_cid)) 0
    assert equal (seq-of (order-path $s.home $adhoc.record.signer $adhoc.edge_cid)) 0
}

# The bytes are not self-addressed, so the formatting is free — but the number
# itself is the root statement's own rule for a counter: decimal, no leading
# zeros, from 0. Pinned as bytes, because a reimplementation reads them.
@test
def "the numbered position states its number as a decimal string" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore

    let bytes = open --raw (order-path $s.home $born.record.signer $born.edge_cid)

    assert equal $bytes "{\n  \"seq\": \"0\"\n}"
}

# One key, one meaning: nothing has to infer the state from whether a proof
# lies beside the file, and a file stating two states at once is not a position
# in either.
@test
def "a position holding two keys or one key with the other value is refused" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing
    let file = order-path $s.home $born.record.signer $born.edge_cid

    for bad in [
        '{"seq": "0", "added_at": "2026-01-01T00:00:00Z"}'
        '{"seq": "2026-01-01T00:00:00Z"}'
        '{"added_at": "0"}'
        # UTC is the rule and not a habit: an offset is the one part of RFC
        # 3339 that lets two files state one instant two ways.
        '{"added_at": "2026-01-01T02:00:00+02:00"}'
        '{}'
    ] {
        $bad | save --raw --force $file
        let err = try { read-position $file; null } catch {|e| $e.msg }

        assert ($err != null) $"read a position out of ($bad)"
    }
}

# --- the seal ---

@test
def "a seal freezes the position beside it and never rewrites it" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    let first = seal --repo $s.repo --no-stamp --allow-untracked-particles
    let proof = order-cert-path $s.home $born.record.signer $born.edge_cid

    assert equal $first.positions 1
    assert equal $first.numbered 1
    assert ($proof | path exists) "the seal catalogued the number and froze nothing"
    let frozen = open --raw $proof

    let second = seal --repo $s.repo --no-stamp --allow-untracked-particles

    assert equal $second.positions 0
    assert equal $second.numbered 0 "a re-seal renumbered a position no longer provisional"
    assert equal (open --raw $proof) $frozen "a later seal rewrote a frozen position proof"
}

# One seal, one snapshot, one bundle: the position is numbered before the
# merkle run, so it enters the same root as the record it counts — and what
# enters that root is the number, never the claimed time.
@test
def "the number enters the same root as the record it counts" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore

    let birth = open --raw (cert-path $s.home $born.record.signer $born.edge_cid) | from json
    let position = open --raw (order-cert-path $s.home $born.record.signer $born.edge_cid) | from json

    assert equal $position.root $birth.root
    assert equal $position.leaf.filepath $"order/($born.record.signer)/($born.edge_cid).order.json"
    assert equal (read-position (order-path $s.home $born.record.signer $born.edge_cid) | columns) [seq]
}

# Without this refusal the number does not do its job: a signer could seal a
# link and simply not number it, and a reader holding the whole graph would see
# a contiguous run beside an uncounted link.
@test
def "a seal refuses a link record no run counts" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing
    let pair = {cid_from: $P1 cid_to: $P3}

    edge-bytes $pair | save --raw (link-path $s.home $born.record.signer (edge-cid $pair))

    let err = try { seal --repo $s.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($err != null) "a seal signed a link outside the run"
    assert str contains $err "link records with no position"
}

@test
def "a seal refuses a position that counts no act" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    write-added-at (order-path $s.home $born.record.signer (edge-cid {cid_from: $P1 cid_to: $P3})) ("2026-01-01T00:00:00Z" | into datetime)

    let err = try { seal --repo $s.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($err != null) "a seal signed a position counting nothing"
    assert str contains $err "positions naming no link record"
}

# The thinning the run exists to expose, done to a graph that was already
# sealed: the act in the middle is gone, record and position together, so the
# numbered run has a hole. It cannot be numbered away — the numbers around it
# are signed — so it is reported, which is the refusal `seal chain` makes about
# a missing snapshot.
@test
def "a seal refuses a numbered run with a hole" [] {
    let s = make-signer $in.tmp_dir
    let born = [[$P1 $P2] [$P1 $P3] [$P2 $P3]] | each {|p| link add $p.0 $p.1 --repo $s.repo --allow-missing }

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore
    let signer = $born | get 0.record.signer
    let hole = $born | where {|l| (seq-of (order-path $s.home $signer $l.edge_cid)) == 1 } | first

    rm (link-path $s.home $signer $hole.edge_cid)
    rm (order-path $s.home $signer $hole.edge_cid)
    rm (order-cert-path $s.home $signer $hole.edge_cid)

    let err = try { seal --repo $s.repo --no-stamp --allow-untracked-particles; null } catch {|e| $e.msg }

    assert ($err != null) "the seal cemented a hole instead of reporting it"
    assert str contains $err "numbered run breaks"
}

# Two checkouts, merged: git stops neither add, since the paths differ and
# nothing conflicts. Their times interleave, so the seal recovers the order the
# acts happened in rather than putting one checkout's whole run before the
# other's — which is what a counter minted at `link add` could only have done.
# Numbering starts after the last number already assigned, and what is already
# signed does not move.
@test
def "the seal numbers the provisional by arrival time after what is already numbered" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore
    let signer = $born.record.signer
    let frozen_proof = open --raw (order-cert-path $s.home $signer $born.edge_cid)

    let late = link add $P1 $P3 --repo $s.repo --allow-missing
    let early = link add $P2 $P3 --repo $s.repo --allow-missing

    write-added-at (order-path $s.home $signer $late.edge_cid) ("2026-02-02T00:00:00Z" | into datetime)
    write-added-at (order-path $s.home $signer $early.edge_cid) ("2026-01-01T00:00:00Z" | into datetime)

    let sealed = seal --repo $s.repo --no-stamp --allow-untracked-particles

    assert equal $sealed.numbered 2
    assert equal (seq-of (order-path $s.home $signer $early.edge_cid)) 1
    assert equal (seq-of (order-path $s.home $signer $late.edge_cid)) 2
    assert equal (seq-of (order-path $s.home $signer $born.edge_cid)) 0
    assert equal (open --raw (order-cert-path $s.home $signer $born.edge_cid)) $frozen_proof
}

# Two acts recorded in the same instant — one commit's worth of backfill, or
# two machines agreeing to the second. The tie-break is byte-wise by edge CID:
# the manifest's own ordering rule, so nothing new decides it.
@test
def "positions claiming the same instant are ordered byte-wise by edge CID" [] {
    let s = make-signer $in.tmp_dir
    let a = link add $P1 $P3 --repo $s.repo --allow-missing
    let b = link add $P2 $P3 --repo $s.repo --allow-missing
    let signer = $a.record.signer

    for edge in [$a.edge_cid $b.edge_cid] {
        write-added-at (order-path $s.home $signer $edge) ("2026-01-01T00:00:00Z" | into datetime)
    }

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore

    let ordered = [$a.edge_cid $b.edge_cid] | sort

    assert equal (seq-of (order-path $s.home $signer ($ordered | first))) 0
    assert equal (seq-of (order-path $s.home $signer ($ordered | last))) 1
}

# --- the reading ---

# The CSV the design asks for, rendered rather than stored: what the run holds
# now, and what the next seal will make of the rest. The projected numbers come
# from the seal's own sort, so an act that arrived earlier takes the earlier
# number whatever order the files were written in.
@test
def "order list states the minted number and the one a provisional position will get" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore
    let late = link add $P1 $P3 --repo $s.repo --allow-missing
    let early = link add $P2 $P3 --repo $s.repo --allow-missing
    let signer = $born.record.signer

    write-added-at (order-path $s.home $signer $late.edge_cid) ("2026-02-02T00:00:00Z" | into datetime)
    write-added-at (order-path $s.home $signer $early.edge_cid) ("2026-01-01T00:00:00Z" | into datetime)
    # A second run under its own signer directory, numbered from 0 of its own.
    let adhoc = link add $P1 $P2 --repo $s.repo --allow-missing --keyless-signer alice

    let run = order list --repo $s.repo

    assert equal ($run | columns) [signer edge seq provisional added_at]
    assert equal ($run | where signer == $signer | select edge seq provisional) [
        {edge: $born.edge_cid seq: 0 provisional: false}
        {edge: $early.edge_cid seq: 1 provisional: true}
        {edge: $late.edge_cid seq: 2 provisional: true}
    ]
    # The number is provable and the time is gone, together: the graph attests
    # no times, so the column empties exactly when the seal mints the number.
    assert equal ($run | where signer == $signer and edge == $born.edge_cid | get 0.added_at) null
    assert equal ($run | where signer == $adhoc.record.signer | get seq) [0]

    # And what it projected is what the seal mints.
    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore
    let sealed = order list --repo $s.repo

    assert equal ($sealed | select signer edge seq) ($run | select signer edge seq)
    assert equal ($sealed | get provisional | uniq) [false]
}

# The refusal `seal` makes, made by the reading for the same reason: numbering
# starts after the highest already assigned, so over a holed run the projection
# would print numbers no seal will ever mint.
@test
def "order list refuses a numbered run with a hole" [] {
    let s = make-signer $in.tmp_dir
    let born = [[$P1 $P2] [$P1 $P3]] | each {|p| link add $p.0 $p.1 --repo $s.repo --allow-missing }

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore
    let signer = $born | get 0.record.signer
    let hole = $born | where {|l| (seq-of (order-path $s.home $signer $l.edge_cid)) == 0 } | first

    rm (order-path $s.home $signer $hole.edge_cid)

    let err = try { order list --repo $s.repo; null } catch {|e| $e.msg }

    assert ($err != null) "the reading projected numbers over a broken run"
    assert str contains $err "numbered run breaks"
}

# --- the bundle and the verdict ---

@test
def "a bundle carries the number and its proof and the seal that froze it" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore

    let out = bundle $born.edge_cid --repo $s.repo --out ($in.tmp_dir | path join out)

    assert ((order-path $out $born.record.signer $born.edge_cid) | path exists) "the bundle carries no number"
    assert ((order-cert-path $out $born.record.signer $born.edge_cid) | path exists) "the bundle carries no proof of the number"
    let root12 = open --raw (order-cert-path $out $born.record.signer $born.edge_cid) | from json | get root | str substring 0..11

    assert (($out | path join seals $root12 tree-root.txt) | path exists) "the bundle carries no seal for the number"
}

# Its own verdict, and deliberately not part of `valid`: SPEC 10 names that
# mistake for the handoff. A tampered number must be reported as unproven while
# the link it counts still verifies — the two are different claims.
@test
def "the number verifies as its own verdict and never as the link validity" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $s.repo --out ($in.tmp_dir | path join out)

    let proven = verify-bundle $out

    assert $proven.valid
    assert equal $proven.position.seq 0
    assert equal $proven.position.added_at null "a proven position states a number, never a time"
    assert $proven.position.valid
    assert $proven.position.bound

    write-added-at (order-path $out $born.record.signer $born.edge_cid) ("2026-01-01T00:00:00Z" | into datetime)
    let tampered = verify-bundle $out

    assert not $tampered.position.valid "a rewritten position still read as proven"
    assert ($tampered.position.error != null)
    assert $tampered.valid "the record stopped verifying because its position was tampered with"
}

# The one refusal own bytes can never reach, so it is built by hand: a bundle
# whose seal covers a position that still states a time. `seal` numbers before
# it stages, so this suite's every other bundle carries a number — but a
# verifier reads what somebody ELSE sealed, and what this one attests is the one
# thing the format says it never does. So the seal is run here directly,
# skipping the numbering step, which is exactly what a foreign implementation
# that never had the rule would produce.
@test
def "a foreign bundle whose seal covers a claimed time is refused" [] {
    use ../nu-cybergraph/_deps/seal.nu [ seal ]
    use ../nu-cybergraph/_deps/merkle.nu [ merkle ]
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing
    let signer = $born.record.signer
    let edge = $born.edge_cid
    let link_rel = link-path $s.home $signer $edge | path relative-to $s.home

    # Everything `nu-cybergraph seal` stages, staged by hand — and nothing that
    # turns the claimed time into a number.
    ^git -C $s.home add -- ($s.home | path join $signer) (order-dir $s.home)
    let root_hex = seal --repo $s.home --no-stamp | get merkle_root
    let snap = snapshot-dir $s.home $root_hex

    mkdir $snap
    for f in (ls ($s.home | path join multiproofs) | where name =~ 'tree-root\.txt' | get name) {
        cp $f $snap
    }
    mkdir (certs-dir $s.home | path join $signer)
    mv (merkle prove $link_rel --repo $s.home | path expand) (cert-path $s.home $signer $edge)
    mv (merkle prove (order-relpath $signer $edge) --repo $s.home | path expand) (order-cert-path $s.home $signer $edge)

    let out = bundle $edge --repo $s.repo --out ($in.tmp_dir | path join out)
    let v = verify-bundle $out

    # The proof folds — this is a real seal over these exact bytes — and the
    # position is refused anyway, on what it states rather than on its crypto.
    assert equal $v.position.seq null
    assert ($v.position.added_at != null) "the hand-built bundle carried a number after all"
    assert not $v.position.valid "a signed claimed time verified as a position"
    assert str contains $v.position.error "still stated"
    # And the act it counts still verifies: the two are different claims.
    assert $v.valid
}

# The graph home answers the same way as a bundle: same checker, same verdict.
@test
def "verify in the repo reports the number too" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore

    let rows = verify $born.edge_cid --repo $s.repo

    assert equal ($rows | get position.seq) [0]
    assert equal ($rows | get position.valid) [true]
}

# A position no proof covers is real and unproven, and that is a state to
# report rather than a failure to raise.
@test
def "a position with no frozen proof reads as unproven" [] {
    let s = make-signer $in.tmp_dir
    let born = link add $P1 $P2 --repo $s.repo --allow-missing

    seal --repo $s.repo --no-stamp --allow-untracked-particles | ignore
    let out = bundle $born.edge_cid --repo $s.repo --out ($in.tmp_dir | path join out)

    rm (order-cert-path $out $born.record.signer $born.edge_cid)

    let v = verify-bundle $out

    assert equal $v.position.seq 0
    assert not $v.position.valid
    assert str contains $v.position.error "no frozen proof"
    assert $v.valid
}

# --- the backfill ---

# Git order is unsigned and the only record of arrival that a pre-run graph
# has, which is what makes it the right one to take. The backfill stamps and
# does not number: the next seal numbers these like anything else, so the
# ordering assertion belongs after it.
@test
def "backfill stamps the graph in the order git recorded" [] {
    let s = make-signer $in.tmp_dir
    let first = link add $P1 $P2 --repo $s.repo --allow-missing
    let second = link add $P1 $P3 --repo $s.repo --allow-missing
    let third = link add $P2 $P3 --repo $s.repo --allow-missing

    # A graph that predates the run: the records are there, the positions are not.
    rm --recursive (order-dir $s.home)
    # Committed out of the order they were written on purpose, so the answer
    # cannot come from the filesystem order or from the edge CIDs. The commit
    # dates are pinned and a month apart: git records seconds, so two commits
    # made in the same second tie, and a tie is decided by the edge CID — which
    # is exactly what this test must not be reading.
    for c in [
        {link: $second at: "2026-01-01T00:00:00Z"}
        {link: $first at: "2026-02-02T00:00:00Z"}
        {link: $third at: "2026-03-03T00:00:00Z"}
    ] {
        ^git -C $s.repo add -- (link-path $s.home $c.link.record.signer $c.link.edge_cid)
        with-env {GIT_AUTHOR_DATE: $c.at GIT_COMMITTER_DATE: $c.at} {
            ^git -C $s.repo commit -q -m $"add ($c.link.edge_cid)"
        }
    }

    # Run in a zone that is not UTC, so `%cI` hands the backfill an offset:
    # the position states UTC whatever the committer's clock was set to.
    let rows = with-env {TZ: "Europe/Moscow"} { order backfill --repo $s.repo }

    assert equal ($rows | columns) [signer edge added_at]
    for r in $rows {
        assert ($r.added_at =~ $RFC3339_UTC_RE) $"($r.edge) was stamped ($r.added_at)"
        assert equal (read-position (order-path $s.home $r.signer $r.edge) | columns) [added_at]
    }
    assert equal ($rows | where edge == $second.edge_cid | get 0.added_at | into datetime) ("2026-01-01T00:00:00Z" | into datetime)

    # And the graph seals: the bijection the backfill exists for is satisfied,
    # and the numbering follows the order git recorded.
    let sealed = seal --repo $s.repo --no-stamp --allow-untracked-particles

    assert equal $sealed.positions 3
    let signer = $first.record.signer

    assert equal (seq-of (order-path $s.home $signer $second.edge_cid)) 0
    assert equal (seq-of (order-path $s.home $signer $first.edge_cid)) 1
    assert equal (seq-of (order-path $s.home $signer $third.edge_cid)) 2
}

# A link git has never seen has no arrival time to take, and the clock would
# invent one. So the backfill refuses and names it — the rule `seal` already
# applies to an untracked store file: committing is the operator's act.
@test
def "backfill refuses a link git has never seen and writes nothing" [] {
    let s = make-signer $in.tmp_dir
    let committed = link add $P1 $P2 --repo $s.repo --allow-missing
    let loose = link add $P1 $P3 --repo $s.repo --allow-missing

    rm --recursive (order-dir $s.home)
    ^git -C $s.repo add -- (link-path $s.home $committed.record.signer $committed.edge_cid)
    ^git -C $s.repo commit -q -m "add one link"

    let err = try { order backfill --repo $s.repo; null } catch {|e| $e.msg }

    assert ($err != null) "the backfill invented an arrival time"
    assert str contains $err "git has never seen"
    assert str contains $err $loose.edge_cid
    assert not ((order-dir $s.home) | path exists) "a refused backfill still stamped the committed half"
}

# Run once, never a migration path the format carries: a half-stamped graph is
# a question about which half, and only its owner can answer it.
@test
def "backfill refuses a graph that already holds a position" [] {
    let s = make-signer $in.tmp_dir

    link add $P1 $P2 --repo $s.repo --allow-missing | ignore

    let err = try { order backfill --repo $s.repo; null } catch {|e| $e.msg }

    assert ($err != null) "backfill re-stamped a graph that already had positions"
    assert str contains $err "already holds"
}
