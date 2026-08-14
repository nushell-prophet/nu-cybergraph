# Bundle verification = nu-multiproof's merkle verify + the cybergraph-specific
# signer binding + the custody chain. Shared by import.nu and verify.nu.

use _deps/merkle.nu [merkle]
use _deps/cid-v0.nu [cid-v0]
use _deps/pubkey.nu [pubkey]
use _deps/ssh-sign.nu [ssh-sign]
use _fs.nu list-files
use _record.nu [read-link]
use _receipt.nu [read-receipt bundle-manifest custody-layers]
use _handoff.nu [read-handoff]
use _layout.nu [receipt-relpath custody-layer-dirname handoff-filename]

# Signer identity is the CID of the pubkey file bytes, so the spec pins one
# encoding: `pubkey canonical` form. A non-canonical file is a malformed
# bundle — reject it loudly, like read-link does for self-addressing.
# One read per pubkey: the canonical check and the binding hash must see
# the same bytes — a re-read could race with a file swap (check vs use).
def canonical-pubkeys [dir: path]: nothing -> table {
    let pubs = list-files ($dir | path join multiproofs pubkeys) --suffix ".pub"
        | each {|f| {path: $f bytes: (open --raw $f | into binary)} }
    for pub in $pubs {
        # decode only to hand text to ssh-keygen; the verdict below is on the
        # bytes. `decode` strips a UTF-8 BOM (so does `decode utf-8` — probed on
        # 0.114.1), so comparing decoded strings accepted `EF BB BF` + the
        # canonical line as canonical while it addresses to a different CID —
        # the one-key-two-identities fork this check exists to close.
        let raw = $pub.bytes | decode utf-8
        # Why the caught error is re-raised with its message intact, and not
        # folded into the refusal below: `pubkey canonical` shells out to
        # OpenSSH, so it throws for reasons that are not about the key at all —
        # nu-multiproof 310c29b names a missing ssh-keygen as a toolchain
        # problem for exactly this reason. A bare `try {}` turned that into
        # "non-canonical pubkey file" over a perfectly good ed25519 key (probed
        # with a PATH holding no ssh-keygen), sending the operator after the
        # wrong problem. Same shape as upstream's own canonical-file, and the
        # same correction as 115d567 one layer up.
        #
        # The wrapper adds the file name and NO verb. It used to prefix upstream's
        # message with "is not an SSH public key", which asserts exactly what
        # upstream's own tail then denies — the operator read "…/x.pub is not an
        # SSH public key: ssh-keygen is not on PATH … This is a toolchain problem,
        # not a problem with the key." One sentence, two verdicts.
        #
        # Any verb is wrong here, because the two throws disagree about what
        # happened. Missing ssh-keygen means nothing was decided at all; a padded
        # copy of a real key (upstream's RSA_PADDED_MODULUS) means OpenSSH read
        # the key FINE and re-encoded it differently — "cannot read it" would be
        # the same contradiction reversed. Upstream knows which of the two it is
        # and says so; it only cannot know which file it was handed. So the
        # wrapper supplies the one missing fact and leaves the verdict alone.
        let canon = try { $raw | pubkey canonical } catch {|e|
            error make {msg: $"($pub.path): ($e.msg)"}
        }
        if $pub.bytes != ($canon | into binary) {
            error make {msg: $"non-canonical pubkey file: ($pub.path) — expected `<type> <base64>` + newline, no comment, no BOM"}
        }
    }
    # The principal a key signs under, derived from the key material — the same
    # digest nu-multiproof renders into its trust list. Computed after the
    # canonical check, which is the one thing that can make it throw.
    $pubs | insert fingerprint {|p| $p.bytes | decode utf-8 | pubkey fingerprint }
}

# One proof root. `dir` is where the leaf resolves and whose multiproofs/pubkeys
# is the trust list; a bundle or a custody layer answers all three by itself.
#
# The two flags exist for the graph home, which answers only the first: its
# certs/ holds hundreds of certificates rather than one, and its
# multiproofs/tree-root.txt is the CURRENT root while a birth certificate always
# belongs to an older seal. Named, those become `certs/<cid>.cert.json` plus
# `seals/<root12>/` and the same checker runs over the repo in place.
#
# Not a second code path: without the flags this behaves exactly as before, and
# `verify` used to buy the same thing by exporting a throwaway bundle per link —
# 567 mktemp + copies over the acceptance graph, ~92ms each, to rearrange paths
# `merkle verify` can now be told directly (nu-multiproof --multiproofs-dir).
def verify-proof-dir [dir: path --cert: path --multiproofs-dir: path]: nothing -> record {
    # Not `default`: it takes a value, so the listing below would run even when
    # the caller named the certificate — and over a graph home it finds none.
    let proof = if $cert != null { $cert } else {
        let certs = list-files $dir --suffix ".cert.json"
        if ($certs | length) != 1 {
            error make {msg: $"expected exactly one *.cert.json at the root of ($dir), found ($certs | length)"}
        }
        $certs | first
    }
    let pubs = canonical-pubkeys $dir
    {v: (merkle verify $proof --repo $dir --multiproofs-dir $multiproofs_dir) pubs: $pubs}
}

# The binding check: does CLAIMED (a signer CID) match a pubkey that validly
# signed these bytes? Without it, anyone could re-seal someone else's record —
# or receipt — under their own key and the signature would still verify,
# against the wrong identity.
#
# Both sides of the match are key material, and that is the whole point. This
# used to read `where name == $s.signer` — the pubkey file's STEM against the
# principal in the verdict row — which made a file name authorize an identity.
# Under nu-multiproof b6d7b11 a principal became the key's own fingerprint, so
# the stem match survived only because `init` happens to name the file after
# it; a bundle is free to name its files anything. Filing the victim's key as
# `<attacker-fingerprint>.pub` (with the attacker's own key beside it under any
# other name, so the trust list still renders it and the signature still
# validates) bound the attacker's signature to the victim's signer CID:
# `valid: true`, `bound: true`, imported by a third repo as the victim's
# authorship. Pinned by tests/test_roundtrip.nu "a pubkey filed under another
# key's fingerprint cannot borrow its authorship".
def bound [sigs: table pubs: table claimed: string]: nothing -> bool {
    let signers = $sigs | where valid | get signer
    $pubs | any {|p| ($p.bytes | cid-v0) == $claimed and $p.fingerprint in $signers }
}

# WHEN the claimed signer endorsed — the other half of `bound`. nu-multiproof
# now stamps every signature over the root statement into the same OTS bundle as
# the root itself (nu-multiproof a38415e), so `merkle verify` returns an
# `endorsements` row per signature that verified. `ots` dates the record's bytes;
# this dates the act of signing them. Without it a valid signature could have
# been made at any time, including after the key was compromised — and that is
# the claim a cybergraph makes, since a link is an assertion by a signer and not
# just a file that existed.
#
# Matched through the same pubkey table as the binding, never through a file
# name: upstream keys the rows by fingerprint (the principal a key signs under),
# and `bound`'s own docstring records what a name-based match cost last time.
#
# null means NOT BOUND, not undated: with no valid signature there is nothing to
# date, while `absent` inside a returned row is the undated case — an endorsement
# nobody stamped.
#
# One signer can have SEVERAL rows, so the best one is chosen rather than the
# first. Upstream builds a row per valid signature FILE, not per signer, and a
# key legitimately has more than one: both sig spellings its `sig-files-for`
# discovers can sit in one bundle (`seal.nu` snapshots both on purpose), and a
# randomized key — ECDSA, ecdsa-sk — makes fresh signature bytes on every seal,
# so re-signing unchanged content yields another valid file rather than the same
# one. Whichever the filesystem happened to list first was then reported, which
# is invisible while every status reads `absent` and a wrong answer the moment
# one of the files is stamped and another is not.
#
# Same rule as nu-multiproof's `pick-stamp`, and for the same reason: the claim
# is "the signer endorsed this no later than T", so the earliest anchor is the
# strongest available and every later one follows from it. Not upstream's
# function itself — it lives in `_stamps.nu`, internal to the repo that owns it.
#
# THREE tiers where upstream has two, and the third is the one this function
# exists for. Upstream picks among candidate proofs, so an unstamped file gives
# it an empty list and never an `absent` candidate — it only ever chooses between
# anchored and pending. Here the rows are per signature FILE and already carry a
# status, so one signer really can hold a `pending` row beside an `absent` one:
# a randomized key signs twice, and only one of those files got stamped. Ranking
# `absent` with `pending` would then report "real but undated" for an endorsement
# whose digest did reach a calendar — under-reporting, never a date invented, but
# still the wrong answer and exactly what "the best one is chosen" denies.
def endorsed-by [ends: table pubs: table claimed: string]: nothing -> any {
    let fingerprints = $pubs | where ($it.bytes | cid-v0) == $claimed | get fingerprint
    let rows = $ends | where signer in $fingerprints
    # Preference order concatenated, then taken from the front: anchored (lowest
    # block) before pending before whatever is left. `$rows` last is the `absent`
    # tier and repeats the earlier ones harmlessly — only index 0 is read.
    $rows | where status == "anchored" | sort-by height
    | append ($rows | where status == "pending")
    | append $rows
    | get --optional 0
}

# One stamp status as one cell: "anchored 912345", "pending", "absent".
#
# Copied rather than imported: upstream's `format-stamp` lives in its
# `_stamps.nu`, and an `_` module is internal to the repo that owns it —
# `_deps/` shims the public modules only. Typed `record` on purpose: passing
# null throws here instead of printing "absent" for a signer with no valid
# signature at all, which is a different verdict and already has its own line.
#
# Exported for the tests alone. Its output goes to `print`, so an end-to-end
# test can reach the anchored data path but never the string this builds from
# it — and the copy above means the version upstream pins by test is not the
# version this repo runs. So the formatting is pinned here directly.
export def stamp-cell [stamp: record]: nothing -> string {
    if $stamp.height? == null { $stamp.status } else { $"($stamp.status) ($stamp.height)" }
}

# A proof dir's outgoing handoff, if present — null when the dir has none
# (exporting without naming a recipient is legal). Checks the signed
# direction claim: shape, the claims it travels with (this link, this
# holder, the holder's exact receipt — null for the author), and a valid
# signature by a pubkey whose CID IS `from` (the handoff twin of the signer
# binding). Whether `to` matches the NEXT holder is the caller's chain check.
# read-handoff requires the schema token byte-exact, so what keeps this
# signature from being replayed as some other artifact is the signed bytes
# themselves — no signature namespace is involved (see _handoff.nu).
def check-handoff [dir: path link_cid: string holder: string expected_receipt: any pubs: table]: nothing -> any {
    let file = $dir | path join (handoff-filename $link_cid)
    if not ($file | path exists) {
        return null
    }
    let h = read-handoff $file
    let claims_ok = $h.link == $link_cid and $h.from == $holder and $h.receipt == $expected_receipt
    # No try/catch: `ssh-sign verify` throws only when it cannot form a verdict
    # at all — no signature file beside the handoff, no pubkey in the bundle,
    # ssh-keygen unusable. Swallowing those into an empty table turned every
    # one of them into "no valid signature by the handoff's `from` signer" —
    # a handoff that COULD NOT be checked reading as a handoff that FAILED a
    # check, and a missing sig file reading as an accusation. A sig that is
    # present but bad is a verdict row (valid: false), which is what the
    # binding below weighs; anything else is a malformed bundle, and this
    # module already throws on those (missing cert, non-canonical pubkey).
    let sigs = ssh-sign verify $file --pubkeys-dir ($dir | path join multiproofs pubkeys)
    let signed = bound $sigs $pubs $h.from
    {
        to: $h.to
        hash: (open --raw $file | hash sha256)
        valid: ($claims_ok and $signed)
        error: (if not $claims_ok {
            "handoff claims do not match the link/holder/receipt it travels with"
        } else if not $signed {
            "no valid signature by the handoff's `from` signer"
        } else { null })
    }
}

# Verify the custody chain of a bundle: one row per layer, in chain order.
# On top of each layer's multiproof result (structure, signature, content,
# OTS), the chain checks:
# - the proven leaf IS this link's receipt at its pinned relative path
# - custodian binding (the receipt-side twin of the signer binding)
# - `files` — the receipt's manifest matches the birth files byte-for-byte
# - `prev` — the receipt hashes the previous layer's receipt file (null for
#   layer 1), which is what proves the order of custody transitively
# - the handoff seam: the receipt's `handoff` must hash the previous holder's
#   handoff file exactly (null when there was none), and that handoff must
#   name THIS custodian as `to` — so a handed-over bundle cannot grow a layer
#   by anyone but the named recipient, and a handoff cannot be stripped
# - the layer's own outgoing handoff, when present (check-handoff)
# - the layer dirname matches its verified content, so naming cannot lie
# Malformed layers (bad name, wrong leaf, unparseable receipt) throw;
# crypto/content/chain mismatches return valid: false rows.
# root_handoff: the author's outgoing handoff (check-handoff on the bundle
# root, null if absent) — the seam checks treat the birth bundle as layer 0.
def verify-custody [bundle: path link_cid: string author: string root_handoff: any]: nothing -> table {
    let layers = custody-layers $bundle
    if ($layers | is-empty) {
        return []
    }
    if ($layers | get index) != (seq 1 ($layers | length)) {
        error make {msg: $"custody layer indices are not contiguous from 1: ($layers | get index | str join ', ')"}
    }
    let birth_files = bundle-manifest $bundle
    # "" = no previous layer yet ("" over null: a mut can't change type)
    mut prev_hash = ""
    mut prev_handoff = $root_handoff
    mut out = []
    for layer in $layers {
        let checked = verify-proof-dir $layer.dir
        let v = $checked.v
        if $v.leaf.filepath != (receipt-relpath $link_cid) {
            error make {msg: $"custody layer ($layer.dir) proves ($v.leaf.filepath), not this link's receipt"}
        }
        let receipt = read-receipt ($layer.dir | path join $v.leaf.filepath)
        if $receipt.link != $link_cid or $receipt.signer != $author {
            error make {msg: $"custody layer ($layer.dir) receipt is for a different link or author"}
        }
        if ($layer.dir | path basename) != (custody-layer-dirname $layer.index $receipt.custodian) {
            error make {msg: $"custody layer dirname ($layer.dir | path basename) does not match its receipt's custodian"}
        }
        let custodian_bound = bound $v.signatures $checked.pubs $receipt.custodian
        let custodian_endorsed = endorsed-by $v.endorsements $checked.pubs $receipt.custodian
        let files_ok = $receipt.files == $birth_files
        let prev_expected = if $prev_hash == "" { null } else { $prev_hash }
        let prev_ok = $receipt.prev == $prev_expected
        let handoff_hash_ok = $receipt.handoff == (if $prev_handoff == null { null } else { $prev_handoff.hash })
        let addressed_ok = $prev_handoff == null or $prev_handoff.to == $receipt.custodian
        let receipt_hash = open --raw ($layer.dir | path join $v.leaf.filepath) | hash sha256
        let own_handoff = check-handoff $layer.dir $link_cid $receipt.custodian $receipt_hash $checked.pubs
        let handoff_ok = $handoff_hash_ok and $addressed_ok and ($own_handoff == null or $own_handoff.valid)
        let valid = $v.valid and $custodian_bound and $files_ok and $prev_ok and $handoff_ok
        let error = if $v.error != null { $v.error } else if not $custodian_bound {
            "receipt's custodian CID matches no validly-signing pubkey in the layer"
        } else if not $files_ok {
            "receipt's files manifest does not match the bundle's birth files"
        } else if not $prev_ok {
            "receipt's prev hash does not match the previous layer's receipt — custody chain broken"
        } else if not $handoff_hash_ok {
            "receipt's handoff hash does not match the previous holder's handoff file"
        } else if not $addressed_ok {
            $"previous holder handed the bundle to ($prev_handoff.to), not to this layer's custodian"
        } else if $own_handoff != null and not $own_handoff.valid {
            $own_handoff.error
        } else { null }
        $prev_hash = $receipt_hash
        $prev_handoff = $own_handoff
        $out = $out | append {
            index: $layer.index
            custodian: $receipt.custodian
            received_at: $receipt.received_at
            bound: $custodian_bound
            endorsed: $custodian_endorsed
            root: $v.root
            handoff: $own_handoff
            valid: $valid
            error: $error
        }
    }
    $out
}

# The columns this repo adds on top of `merkle verify`'s verdict, in the state
# they take when nothing could be read. Written once because `verify-bundle` has
# two exits sixty lines apart, and both used to spell the whole set out. 170a0e7
# is where that started: the tail had grown these five over several commits, and
# the new early exit copied all five at once rather than sharing them — the
# defect 022585d named in `link add`, and from then on every column would cost
# two edits.
# The tail merges its real values over these, so a column added here appears at
# the unreadable exit without an edit.
const UNREAD_COLUMNS = {
    record: null
    signer: {cid: null bound: false endorsed: null}
    handoff: null
    custody: []
    handed_to: null
}

# Add those columns to an upstream verdict, raising if upstream already has one
# of the names.
#
# `insert` in a fold and not `merge`, which was the first shape of this: `merge`
# overwrites in silence, and these five names are added to a record this repo
# does not own. Upstream grows columns — `content_enumeration` arrived from
# nu-multiproof between two refreshes of docs/20260730-two-stamp-ergo-check.nu —
# so an upstream `record` or `signer` some day is a real event, not a
# hypothetical. `insert` stops the run and names the column; `merge` would hide
# upstream's answer under this repo's default, and `custody: []` reads as "no
# custody layers" rather than as "something went wrong".
def add-columns [v: record cols: record]: nothing -> record {
    $cols | items {|name value| {name: $name value: $value} }
    | reduce --fold $v {|c acc| $acc | insert $c.name $c.value }
}

# Verify a portable bundle directory: the birth proof (multiproof result +
# SIGNER BINDING — the record's `signer` must be the CID of a pubkey that
# validly signed the root statement), then every custody layer on top.
#
# The flags pass straight to verify-proof-dir, so `verify` can point this at the
# graph home instead of at an exported copy of it. Everything below is unchanged
# by that: the leaf resolves under `bundle` either way (`links/<cid>.json` is the
# same relative path in a bundle and in the graph home — that is why the export
# reproduced it), and a graph home carries no handoff and no custody/, so those
# two checks answer null and [] exactly as they do for a birth bundle.
export def verify-bundle [bundle: path --cert: path --multiproofs-dir: path]: nothing -> record {
    let birth = verify-proof-dir $bundle --cert $cert --multiproofs-dir $multiproofs_dir
    let v = $birth.v

    # When the leaf is not a readable regular file, `merkle verify` has already
    # decided the bundle is invalid AND written the reason. Reading the record
    # anyway threw `nu::shell::io::not_found` from `open`, so the structured
    # verdict that names the actual defect never reached the caller — the layer
    # that knew why computed the answer and then discarded it.
    #
    # Keyed on the TYPE, not on a list of statuses: upstream returns a bool when
    # the path resolved to a real file (true = bytes match, false = they do not)
    # and a string naming the divergence otherwise — missing, symlink, outside,
    # directory, unverifiable. A status added upstream is covered without an
    # edit here, and the enumeration cannot drift out of sync.
    #
    # `false` deliberately continues: the file IS there and readable, and
    # `read-link` enforces a different contract from the merkle proof — bytes
    # against their own filename. A present but non-canonical record must keep
    # throwing its own message, so this must never become a `try` around the
    # read.
    if ($v.content_verified | describe) != "bool" {
        return (add-columns ($v | reject ots) $UNREAD_COLUMNS)
    }

    # read-link throws on a record that fails self-addressing — tampered bytes
    # never reach the binding check.
    let rec = read-link ($bundle | path join $v.leaf.filepath)
    let signer_bound = bound $v.signatures $birth.pubs $rec.signer
    let signer_endorsed = endorsed-by $v.endorsements $birth.pubs $rec.signer
    # No `\(`: that is an escape only in `$"…"`. Inside the `'…'` here the
    # backslash is literal, and it printed as one. Parens need no escaping in a
    # single-quoted string — nothing interpolates there.
    let signer_line = if $signer_bound {
        $"bound, endorsement (stamp-cell $signer_endorsed)"
    } else {
        'NOT BOUND (no valid signature by the claimed signer)'
    }
    print $"signer:    ($signer_line)"

    let link_cid = $v.leaf.filepath | path parse | get stem
    let root_handoff = check-handoff $bundle $link_cid $rec.signer null $birth.pubs
    let custody = verify-custody $bundle $link_cid $rec.signer $root_handoff
    let custody_ok = $custody | all { $in.valid }
    let root_handoff_ok = $root_handoff == null or $root_handoff.valid
    if ($custody | is-not-empty) {
        print $"custody:   ($custody | length) layers, (if $custody_ok { 'chain valid' } else { 'CHAIN INVALID' })"
    }

    # The tail handoff is the one no later layer has consumed: whoever imports
    # this bundle is the recipient it names (import enforces that).
    let tail_handoff = if ($custody | is-empty) { $root_handoff } else { $custody | last | get handoff }
    # Only a VALID tail handoff names an addressee — a tampered one already
    # fails verification, but a caller keying on handed_to alone must not be
    # handed its forged `to`.
    let handed_to = if $tail_handoff == null or not $tail_handoff.valid { null } else { $tail_handoff.to }
    if $handed_to != null {
        print $"handoff:   addressed to ($handed_to)"
    }

    # `ots` is dropped, not renamed or defaulted. It is upstream's content anchor,
    # and `seal.nu` always passes --no-content-anchor, so in a cybergraph bundle it
    # is `absent` on every row — forever. A permanently empty field is worse than
    # noise here: `absent` reads as "this link carries no timestamp" when the link
    # IS dated, by `signer.endorsed`. Leaving it would re-pose the one question
    # dropping the second anchor exists to answer — which of these two is the time.
    #
    # `endorsements` stays: it lists every signer who endorsed this root, which is
    # a different question from when THIS record's signer did. One answer each,
    # not two answers to one.
    #
    # Upstream still PRINTS `ots: absent` from `merkle verify`. Silencing that
    # needs a change there, not a filter here.
    # The real values merge over UNREAD_COLUMNS, not over the verdict: that
    # overwrite is this repo's own defaults giving way to this repo's own
    # answers, which is nothing like overwriting a column upstream returned.
    add-columns ($v | reject ots) ($UNREAD_COLUMNS | merge {
        record: $rec
        signer: {cid: $rec.signer bound: $signer_bound endorsed: $signer_endorsed}
        handoff: $root_handoff
        custody: $custody
        handed_to: $handed_to
    })
    | update valid ($v.valid and $signer_bound and $root_handoff_ok and $custody_ok)
    | update error (if $v.error != null { $v.error } else if not $signer_bound {
        "record's signer CID matches no validly-signing pubkey in the bundle"
    } else if not $root_handoff_ok {
        $root_handoff.error
    } else if not $custody_ok {
        ($custody | where not valid | first | get error)
    } else { null })
}
