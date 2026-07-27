# Assemble the portable bundle for one link: everything a stranger needs to
# verify it offline, in the layout nu-multiproof's README pins under
# "Verifying without the origin repo".
#
# An OWN link (has a birth certificate in certs/) exports the birth bundle.
# An IMPORTED link re-exports: the foreign bundle copied unchanged — it stays
# the authority for authorship and birth time — plus this repo's custody
# layer appended under custody/<n>-<neuron12>/. A custody layer is itself a
# proof bundle in the same layout, over the receipt instead of the record,
# so the same verification machinery covers both.

use _deps/ssh-sign.nu [ssh-sign]
use _deps/pubkey.nu [pubkey]
use _repo.nu graph-root
use _fs.nu [list-files list-dirs]
use _layout.nu [
    links-dir exports-dir cert-path cert-filename snapshot-dir imported-copies
    receipt-relpath receipt-cert-path receipt-cert-filename custody-dir custody-layer-dirname
    handoff-filename
]
use _record.nu [CID_V0_RE]
use _receipt.nu [read-receipt custody-layers own-neuron]
use _handoff.nu [handoff-bytes HANDOFF_SCHEMA]

# Copy one seal's verification artifacts into a proof dir: the snapshot's
# root statement + signatures, the signer pubkeys, and the OTS bundles
# committing to that root. Shared by the birth bundle and custody layers.
def assemble-seal-artifacts [root: path out: path root_hex: string] {
    let snap = snapshot-dir $root $root_hex
    if not ($snap | path exists) {
        error make {msg: $"seal snapshot missing for root ($root_hex) — the proof predates the seals/ convention?"}
    }
    mkdir ($out | path join multiproofs pubkeys)
    list-files $snap | each {|f| cp $f ($out | path join multiproofs) }

    # Signer pubkeys, found by KEY MATERIAL. The middle segment of a sig name is
    # the signer's fingerprint (nu-multiproof b6d7b11: `sig-path-for` names the
    # file after `signing-principal`, which is the key's own digest), while a
    # pubkey file's name is decoration — upstream pins that a key registered
    # under any name still signs and verifies. Joining the segment onto
    # `pubkeys/<name>.pub` therefore shipped a bundle with no signer key at all
    # for any neuron who renamed the file `init` wrote.
    # Anchored regex, greedy middle: a fingerprint cannot contain ".sig", but
    # the bare `<file>.sig` form must not parse as one either.
    let signers = list-files $snap --suffix ".sig"
        | each {|s| $s | path basename | parse --regex '^tree-root\.txt\.(?<fp>.+)\.sig$' | get --optional 0.fp }
    let registered = list-files ($root | path join multiproofs pubkeys) --suffix ".pub"
        | each {|f| {path: $f fingerprint: (open --raw $f | pubkey fingerprint)} }
    let copied = $signers | each {|fp|
        let hit = $registered | where fingerprint == $fp
        if ($hit | is-empty) { null } else {
            cp ($hit | first | get path) ($out | path join multiproofs pubkeys)
            $fp
        }
    }
    if ($copied | is-empty) {
        error make {msg: "no signer pubkey found for the snapshot's signatures — the bundle could never verify"}
    }

    # OTS bundles committing to this root, matched by their frozen root
    # statement. Plain content match — discovery only; verify re-checks the
    # commitment cryptographically.
    let ots_bundles = list-dirs ($root | path join multiproofs ots-timestamps)
        | where {|d| $d | path basename | str starts-with "tree-root." }
        | where {|d|
            let frozen = $d | path join tree-root.txt
            ($frozen | path exists) and (open --raw $frozen | str contains $root_hex)
        }
    if ($ots_bundles | is-empty) {
        print "note: no OTS bundle for this root (sealed with --no-stamp?) — the bundle's timestamp will report absent"
    } else {
        mkdir ($out | path join multiproofs ots-timestamps)
        $ots_bundles | each {|d|
            cp -r $d ($out | path join multiproofs ots-timestamps ($d | path basename))
        }
    }
}

# Resolve and validate the handoff signing key: --key, else git config
# user.signingKey. main runs this BEFORE the destination dir is created —
# same discipline as seal's pre-checks: a key error after assembly leaves a
# complete-looking bundle whose handoff is unsigned, and the retry is then
# blocked by "bundle destination already exists".
def resolve-handoff-key [root: path key: any]: nothing -> path {
    let resolved = if $key != null { $key } else {
        let k = ^git -C $root config user.signingKey | complete
        if $k.exit_code != 0 or ($k.stdout | str trim | is-empty) {
            error make {msg: "handoff needs a signing key: set git config user.signingKey or pass --key"}
        }
        $k.stdout | str trim | path expand
    }
    if not ($resolved | path exists) {
        error make {msg: $"handoff signing key not found: ($resolved)"}
    }
    $resolved
}

# Write and sign the sender's handoff into a proof dir. Signed directly with
# the repo's key, not through a seal: the bundle leaves at export time,
# before any later seal could catalogue the handoff — a detached signature
# is the only immediate, local authentication available.
def write-handoff [root: path dir: path link_cid: string to: string receipt_hash: any key: path] {
    let handoff = {
        schema: $HANDOFF_SCHEMA
        link: $link_cid
        from: (own-neuron $root)
        to: $to
        receipt: $receipt_hash
        handed_at: (date now | format date "%+")
    }
    let file = $dir | path join (handoff-filename $link_cid)
    handoff-bytes $handoff | save --raw $file
    ssh-sign sign $file --key $key --pubkeys-dir ($root | path join multiproofs pubkeys)
}

# The writer's own exit check — the same root-cert test import runs first.
# Observed once: an interior `cp -r` error was printed but not raised, and a
# custody re-export shipped with the birth bundle missing entirely, exit 0.
# Whatever the cause, a partial bundle must not leave the repo with exit 0 —
# and must not stay on disk looking complete, so it is removed before erroring.
def assert-complete-bundle [out: path]: nothing -> path {
    let certs = list-files $out --suffix ".cert.json"
    if ($certs | length) != 1 {
        rm --recursive --force $out
        error make {msg: $"bundle came out incomplete: ($certs | length) *.cert.json at the root instead of 1 — partial bundle removed, re-run the export"}
    }
    $out
}

# Export a link as a portable, offline-verifiable bundle: the birth bundle
# for an own link; for an imported link, the foreign bundle unchanged plus
# this repo's custody layer. --to names the recipient in a signed handoff.
export def main [
    link_cid: string # CID of a link: authored here (certs/) or imported (imported/*/)
    --repo: path # Source repo root (default: git root of current directory)
    --out: path # Bundle destination (default: exports/<link_cid>)
    --to: string # Recipient neuron CID — adds a signed handoff (default: none, an open export)
    --key: path # SSH private key for the handoff signature (default: from git config user.signingKey)
]: nothing -> path {
    let root = graph-root $repo
    if $to != null and $to !~ $CID_V0_RE {
        error make {msg: $"--to must be a neuron CID \(base58btc CID v0\): ($to)"}
    }
    let key = if $to == null { null } else { resolve-handoff-key $root $key }
    let out = if $out != null { $out | path expand } else { exports-dir $root | path join $link_cid }
    if ($out | path exists) {
        error make {msg: $"bundle destination already exists: ($out)"}
    }

    let cert = cert-path $root $link_cid
    if ($cert | path exists) {
        # Own link: the birth bundle
        let proof = open --raw $cert | from json
        mkdir (links-dir $out)
        cp ($root | path join $proof.leaf.filepath) (links-dir $out)
        cp $cert ($out | path join (cert-filename $link_cid))
        assemble-seal-artifacts $root $out $proof.root
        if $to != null {
            # The author has no receipt — their handoff pins nothing but the link
            write-handoff $root $out $link_cid $to null $key
        }
        return (assert-complete-bundle $out)
    }

    # Imported link: re-export with this repo's custody layer appended
    let hits = imported-copies $root $link_cid
    if ($hits | is-empty) {
        error make {msg: $"unknown link: ($link_cid) — no birth certificate in certs/ and nothing in imported/"}
    }
    let rcert = receipt-cert-path $root $link_cid
    if not ($rcert | path exists) {
        error make {msg: $"no frozen receipt proof for ($link_cid) — run `nu-cybergraph seal` after import, then re-export"}
    }
    cp -r ($hits | first) $out

    let receipt = read-receipt ($root | path join (receipt-relpath $link_cid))
    let index = (custody-layers $out | length) + 1
    let layer = custody-dir $out | path join (custody-layer-dirname $index $receipt.custodian)
    let proof = open --raw $rcert | from json
    mkdir ($layer | path join ((receipt-relpath $link_cid) | path dirname))
    cp ($root | path join (receipt-relpath $link_cid)) ($layer | path join (receipt-relpath $link_cid))
    cp $rcert ($layer | path join (receipt-cert-filename $link_cid))
    assemble-seal-artifacts $root $layer $proof.root
    if $to != null {
        # A custodian's handoff pins their receipt — the exact chain state handed over
        let receipt_hash = open --raw ($root | path join (receipt-relpath $link_cid)) | hash sha256
        write-handoff $root $layer $link_cid $to $receipt_hash $key
    }
    assert-complete-bundle $out
}
