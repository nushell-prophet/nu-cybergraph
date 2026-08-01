# Assemble the portable bundle for one link: everything a stranger needs to
# verify it offline, in the layout nu-multiproof's README pins under
# "Verifying without the origin repo".
#
# An OWN link (has a birth certificate in certs/) exports the birth bundle.
# An IMPORTED link re-exports: the foreign bundle copied unchanged — it stays
# the authority for authorship and birth time — plus this repo's custody
# layer appended under custody/<n>-<signer12>/. A custody layer is itself a
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
use _validate.nu [CID_V0_RE]
use _receipt.nu [read-receipt custody-layers]
use _signer.nu [own-signer]
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
    # for any signer who renamed the file `init` wrote.
    # Anchored regex, greedy middle: a fingerprint cannot contain ".sig", but
    # the bare `<file>.sig` form must not parse as one either.
    let signers = list-files $snap --suffix ".sig"
        | each { path basename | parse --regex '^tree-root\.txt\.(?<fp>.+)\.sig$' | get --optional 0.fp }
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
        | where ($it | path basename | str starts-with "tree-root.")
        | where {|d|
            let frozen = $d | path join tree-root.txt
            ($frozen | path exists) and (open --raw $frozen | str contains $root_hex)
        }
    if ($ots_bundles | is-empty) {
        print "note: no OTS bundle for this root (sealed with --no-stamp?) — the bundle's timestamp will report absent"
    } else {
        mkdir ($out | path join multiproofs ots-timestamps)
        $ots_bundles | each {|d|
            cp --recursive $d ($out | path join multiproofs ots-timestamps ($d | path basename))
        }
    }
}

# Resolve the handoff signing key: --key, else the GRAPH REPO's git config.
# Why not leave it to `ssh-sign sign`, whose --key already defaults from git
# config: upstream resolves it in the current directory (`resolve-signing-key`
# takes a --root the `sign` path does not expose), and the graph is usually
# not the directory the operator stands in — the suite proved it, every
# temp-repo export fell back to the wrong config.
#
# What this deliberately does NOT check is what makes a key USABLE: a `.pub`
# beside it and its fingerprint registered in pubkeys/. Those are upstream's
# rules — `ssh-sign sign` -> `signing-principal`, nu-multiproof b6d7b11, "a
# principal is not the signer's to choose" — and a copy here would enforce one
# invariant in two places, drifting the moment upstream narrows it again (it
# just did). main's cleanup is what makes their refusal survivable.
def resolve-handoff-key [root: path key: any]: nothing -> path {
    if $key != null { return $key }
    let k = ^git -C $root config user.signingKey | complete
    if $k.exit_code != 0 or ($k.stdout | str trim | is-empty) {
        error make {msg: "handoff needs a signing key: set git config user.signingKey or pass --key"}
    }
    let raw = $k.stdout | str trim
    # git's inline form carries the key material instead of a path. Upstream
    # signs with it by materializing a temp file and owning its lifetime
    # (`with-signing-key`); reproducing that here would be a second copy of
    # someone else's cleanup rule, so the handoff names the gap instead of
    # failing later as "signing key not found: key::ssh-ed25519 AAAA…".
    if ($raw | str starts-with "key::") {
        error make {msg: "handoff cannot sign with an inline `key::` user.signingKey — pass --key with the key file"}
    }
    $raw | path expand
}

# Write and sign the sender's handoff into a proof dir. Signed directly with
# the repo's key, not through a seal: the bundle leaves at export time,
# before any later seal could catalogue the handoff — a detached signature
# is the only immediate, local authentication available.
def write-handoff [root: path dir: path link_cid: string to: string receipt_hash: any key: path] {
    let handoff = {
        schema: $HANDOFF_SCHEMA
        link: $link_cid
        from: (own-signer $root)
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
# Whatever the cause, a partial bundle must not leave the repo with exit 0.
# Removing it is main's job, not this one's: every failure below the "already
# exists" check leaves the same debris, so one cleanup covers them all.
def assert-complete-bundle [out: path] {
    let certs = list-files $out --suffix ".cert.json"
    if ($certs | length) != 1 {
        error make {msg: $"bundle came out incomplete: ($certs | length) *.cert.json at the root instead of 1 — partial bundle removed, re-run the export"}
    }
}

# Everything that writes into the destination dir. Split out of main so the
# whole of it sits under one cleanup: from here down, any raise leaves debris.
def assemble-bundle [root: path out: path link_cid: string to: any key: any] {
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
        return
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
    cp --recursive ($hits | first) $out

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
}

# Export a link as a portable, offline-verifiable bundle: the birth bundle
# for an own link; for an imported link, the foreign bundle unchanged plus
# this repo's custody layer. --to names the recipient in a signed handoff.
export def main [
    link_cid: string # CID of a link: authored here (certs/) or imported (imported/*/)
    --repo: path # Source repo root (default: git root of current directory)
    --out: path # Bundle destination (default: exports/<link_cid>)
    --to: string # Recipient signer CID — adds a signed handoff (default: none, an open export)
    --key: path # SSH private key for the handoff signature (default: from git config user.signingKey)
]: nothing -> path {
    let root = graph-root $repo
    if $to != null and $to !~ $CID_V0_RE {
        error make {msg: $"--to must be a signer CID \(base58btc CID v0\): ($to)"}
    }
    let key = if $to == null { null } else { resolve-handoff-key $root $key }
    let out = if $out != null { $out | path expand } else { exports-dir $root | path join $link_cid }
    if ($out | path exists) {
        error make {msg: $"bundle destination already exists: ($out)"}
    }

    # Why a cleanup and not more pre-checks: a raise below this line — an
    # unregistered signing key most of all (see resolve-handoff-key) — used to
    # leave a complete-looking bundle whose handoff was unsigned, and the retry
    # then hit "bundle destination already exists" above. The dir did not exist
    # before, so removing it restores exactly the state the export started in,
    # for every cause rather than the one a pre-check could name. The error is
    # re-raised raw: labels, help and location are the operator's evidence.
    try {
        assemble-bundle $root $out $link_cid $to $key
        assert-complete-bundle $out
    } catch {|e|
        rm --recursive --force $out
        error make $e.raw
    }
    $out
}
