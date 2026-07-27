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
        let raw = $pub.bytes | decode
        # Why the caught error is re-raised with its message intact, and not
        # folded into the refusal below: `pubkey canonical` shells out to
        # OpenSSH, so it throws for reasons that are not about the key at all —
        # nu-multiproof 310c29b names a missing ssh-keygen as a toolchain
        # problem for exactly this reason. A bare `try {}` turned that into
        # "non-canonical pubkey file" over a perfectly good ed25519 key (probed
        # with a PATH holding no ssh-keygen), sending the operator after the
        # wrong problem. Same shape as upstream's own canonical-file, and the
        # same correction as 115d567 one layer up.
        let canon = try { $raw | pubkey canonical } catch {|e|
            error make {msg: $"($pub.path) is not an SSH public key: ($e.msg)"}
        }
        if $raw != $canon {
            error make {msg: $"non-canonical pubkey file: ($pub.path) — expected `<type> <base64>` + newline, no comment"}
        }
    }
    # The principal a key signs under, derived from the key material — the same
    # digest nu-multiproof renders into its trust list. Computed after the
    # canonical check, which is the one thing that can make it throw.
    $pubs | insert fingerprint {|p| $p.bytes | decode | pubkey fingerprint }
}

# One proof directory — a birth bundle or a custody layer, same layout: a
# single *.cert.json at the root, the leaf file at its manifest path, the
# seal snapshot + pubkeys under multiproofs/.
def verify-proof-dir [dir: path]: nothing -> record {
    let certs = list-files $dir --suffix ".cert.json"
    if ($certs | length) != 1 {
        error make {msg: $"expected exactly one *.cert.json at the root of ($dir), found ($certs | length)"}
    }
    let pubs = canonical-pubkeys $dir
    {v: (merkle verify ($certs | first) --repo $dir) pubs: $pubs}
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
            root: $v.root
            ots: $v.ots
            handoff: $own_handoff
            valid: $valid
            error: $error
        }
    }
    $out
}

# Verify a portable bundle directory: the birth proof (multiproof result +
# SIGNER BINDING — the record's `signer` must be the CID of a pubkey that
# validly signed the root statement), then every custody layer on top.
export def verify-bundle [bundle: path]: nothing -> record {
    let birth = verify-proof-dir $bundle
    let v = $birth.v

    # read-link throws on a record that fails self-addressing — tampered bytes
    # never reach the binding check.
    let rec = read-link ($bundle | path join $v.leaf.filepath)
    let signer_bound = bound $v.signatures $birth.pubs $rec.signer
    # No `\(`: that is an escape only in `$"…"`. Inside the `'…'` here the
    # backslash is literal, and it printed as one. Parens need no escaping in a
    # single-quoted string — nothing interpolates there.
    print $"signer:    (if $signer_bound { 'bound' } else { 'NOT BOUND (no valid signature by the claimed signer)' })"

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

    $v
    | insert record $rec
    | insert signer {cid: $rec.signer bound: $signer_bound}
    | insert handoff $root_handoff
    | insert custody $custody
    | insert handed_to $handed_to
    | update valid ($v.valid and $signer_bound and $root_handoff_ok and $custody_ok)
    | update error (if $v.error != null { $v.error } else if not $signer_bound {
        "record's signer CID matches no validly-signing pubkey in the bundle"
    } else if not $root_handoff_ok {
        $root_handoff.error
    } else if not $custody_ok {
        ($custody | where not valid | first | get error)
    } else { null })
}
