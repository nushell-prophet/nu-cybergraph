# Bundle verification = nu-multiproof's merkle verify + the cybergraph-specific
# neuron binding. Shared by import.nu and verify.nu.

use _deps.nu [merkle cid-v0 pubkey]
use _record.nu [read-link]

# Verify a portable bundle directory. On top of the multiproof result
# (structure, signature, content, OTS), checks the NEURON BINDING: the
# record's `neuron` field must be the CID of a pubkey that validly signed the
# root statement. Without it, anyone could re-sign someone else's record with
# their own key and claim authorship — the signature would verify, but against
# the wrong identity.
export def verify-bundle [bundle: path]: nothing -> record {
    let certs = glob ($bundle | path join *.cert.json)
    if ($certs | length) != 1 {
        error make {msg: $"expected exactly one *.cert.json at the bundle root, found ($certs | length) in ($bundle)"}
    }
    # Neuron identity is the CID of the pubkey file bytes, so the spec pins one
    # encoding: `pubkey canonical` form. A non-canonical file is a malformed
    # bundle — reject it loudly, like read-link does for self-addressing.
    for pub in (glob ($bundle | path join multiproofs pubkeys *.pub)) {
        let raw = open --raw $pub | into string
        if $raw != (try { $raw | pubkey canonical }) {
            error make {msg: $"non-canonical pubkey file: ($pub) — expected `<type> <base64>` + newline, no comment"}
        }
    }
    let v = merkle verify ($certs | first) --repo $bundle

    # read-link throws on a record that fails self-addressing — tampered bytes
    # never reach the binding check.
    let rec = read-link ($bundle | path join $v.leaf.filepath)
    let bound = $v.signatures | where valid | any {|s|
        let pub = $bundle | path join multiproofs pubkeys $"($s.signer).pub"
        ($pub | path exists) and ((open --raw $pub | into binary | cid-v0) == $rec.neuron)
    }
    print $"neuron:    (if $bound { 'bound' } else { 'NOT BOUND \(no valid signature by the claimed neuron\)' })"

    $v
    | insert record $rec
    | insert neuron {cid: $rec.neuron bound: $bound}
    | update valid ($v.valid and $bound)
    | update error (if $v.error != null { $v.error } else if not $bound {
        "record's neuron CID matches no validly-signing pubkey in the bundle"
    } else { null })
}
