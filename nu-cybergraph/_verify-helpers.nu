# Bundle verification = nu-multiproof's merkle verify + the cybergraph-specific
# neuron binding + the custody chain. Shared by import.nu and verify.nu.

use _deps.nu [merkle cid-v0 pubkey]
use _record.nu [read-link]
use _receipt.nu [read-receipt bundle-manifest custody-layers]
use _layout.nu [receipt-relpath custody-layer-dirname]

# Neuron identity is the CID of the pubkey file bytes, so the spec pins one
# encoding: `pubkey canonical` form. A non-canonical file is a malformed
# bundle — reject it loudly, like read-link does for self-addressing.
# One read per pubkey: the canonical check and the binding hash must see
# the same bytes — a re-read could race with a file swap (check vs use).
def canonical-pubkeys [dir: path]: nothing -> table {
    let pubs = glob ($dir | path join multiproofs pubkeys *.pub)
        | each {|f| {path: $f name: ($f | path parse | get stem) bytes: (open --raw $f | into binary)} }
    for pub in $pubs {
        let raw = $pub.bytes | decode
        if $raw != (try { $raw | pubkey canonical }) {
            error make {msg: $"non-canonical pubkey file: ($pub.path) — expected `<type> <base64>` + newline, no comment"}
        }
    }
    $pubs
}

# One proof directory — a birth bundle or a custody layer, same layout: a
# single *.cert.json at the root, the leaf file at its manifest path, the
# seal snapshot + pubkeys under multiproofs/.
def verify-proof-dir [dir: path]: nothing -> record {
    let certs = glob ($dir | path join *.cert.json)
    if ($certs | length) != 1 {
        error make {msg: $"expected exactly one *.cert.json at the root of ($dir), found ($certs | length)"}
    }
    let pubs = canonical-pubkeys $dir
    {v: (merkle verify ($certs | first) --repo $dir) pubs: $pubs}
}

# The binding check: does CLAIMED (a neuron CID) match a pubkey that validly
# signed this proof's root statement? Without it, anyone could re-seal
# someone else's record — or receipt — under their own key and the signature
# would still verify, against the wrong identity.
def bound [v: record pubs: table claimed: string]: nothing -> bool {
    $v.signatures | where valid | any {|s|
        $pubs | where name == $s.signer | any {|p| ($p.bytes | cid-v0) == $claimed }
    }
}

# Verify the custody chain of a bundle: one row per layer, in chain order.
# On top of each layer's multiproof result (structure, signature, content,
# OTS), the chain checks:
# - the proven leaf IS this link's receipt at its pinned relative path
# - custodian binding (the receipt-side twin of the neuron binding)
# - `files` — the receipt's manifest matches the birth files byte-for-byte
# - `prev` — the receipt hashes the previous layer's receipt file (null for
#   layer 1), which is what proves the order of custody transitively
# - the layer dirname matches its verified content, so naming cannot lie
# Malformed layers (bad name, wrong leaf, unparseable receipt) throw;
# crypto/content/chain mismatches return valid: false rows.
def verify-custody [bundle: path link_cid: string author: string]: nothing -> table {
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
    mut out = []
    for layer in $layers {
        let checked = verify-proof-dir $layer.dir
        let v = $checked.v
        if $v.leaf.filepath != (receipt-relpath $link_cid) {
            error make {msg: $"custody layer ($layer.dir) proves ($v.leaf.filepath), not this link's receipt"}
        }
        let receipt = read-receipt ($layer.dir | path join $v.leaf.filepath)
        if $receipt.link != $link_cid or $receipt.neuron != $author {
            error make {msg: $"custody layer ($layer.dir) receipt is for a different link or author"}
        }
        if ($layer.dir | path basename) != (custody-layer-dirname $layer.index $receipt.custodian) {
            error make {msg: $"custody layer dirname ($layer.dir | path basename) does not match its receipt's custodian"}
        }
        let custodian_bound = bound $v $checked.pubs $receipt.custodian
        let files_ok = $receipt.files == $birth_files
        let prev_expected = if $prev_hash == "" { null } else { $prev_hash }
        let prev_ok = $receipt.prev == $prev_expected
        let valid = $v.valid and $custodian_bound and $files_ok and $prev_ok
        let error = if $v.error != null { $v.error } else if not $custodian_bound {
            "receipt's custodian CID matches no validly-signing pubkey in the layer"
        } else if not $files_ok {
            "receipt's files manifest does not match the bundle's birth files"
        } else if not $prev_ok {
            "receipt's prev hash does not match the previous layer's receipt — custody chain broken"
        } else { null }
        $prev_hash = open --raw ($layer.dir | path join $v.leaf.filepath) | hash sha256
        $out = $out | append {
            index: $layer.index
            custodian: $receipt.custodian
            received_at: $receipt.received_at
            bound: $custodian_bound
            root: $v.root
            ots: $v.ots
            valid: $valid
            error: $error
        }
    }
    $out
}

# Verify a portable bundle directory: the birth proof (multiproof result +
# NEURON BINDING — the record's `neuron` must be the CID of a pubkey that
# validly signed the root statement), then every custody layer on top.
export def verify-bundle [bundle: path]: nothing -> record {
    let birth = verify-proof-dir $bundle
    let v = $birth.v

    # read-link throws on a record that fails self-addressing — tampered bytes
    # never reach the binding check.
    let rec = read-link ($bundle | path join $v.leaf.filepath)
    let neuron_bound = bound $v $birth.pubs $rec.neuron
    print $"neuron:    (if $neuron_bound { 'bound' } else { 'NOT BOUND \(no valid signature by the claimed neuron\)' })"

    let link_cid = $v.leaf.filepath | path parse | get stem
    let custody = verify-custody $bundle $link_cid $rec.neuron
    let custody_ok = $custody | all { $in.valid }
    if ($custody | is-not-empty) {
        print $"custody:   ($custody | length) layers, (if $custody_ok { 'chain valid' } else { 'CHAIN INVALID' })"
    }

    $v
    | insert record $rec
    | insert neuron {cid: $rec.neuron bound: $neuron_bound}
    | insert custody $custody
    | update valid ($v.valid and $neuron_bound and $custody_ok)
    | update error (if $v.error != null { $v.error } else if not $neuron_bound {
        "record's neuron CID matches no validly-signing pubkey in the bundle"
    } else if not $custody_ok {
        ($custody | where not valid | first | get error)
    } else { null })
}
