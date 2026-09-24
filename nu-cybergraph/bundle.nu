# Assemble the portable bundle for one link: everything a stranger needs to
# verify it offline, in the layout nu-multiproof's README pins under
# "Verifying without the origin repo".
#
# An OWN link (has a birth certificate in certs/) exports the birth bundle,
# plus the particle files its two ends address (when this repo holds them) —
# without them an importer has the record but not the preimage of the
# instruction it names (bj002 "Reading instructions"), and can only decode
# the edge's meaning by scanning particles/ across every repo it can reach.
# --links-only drops the bundle to the record and the proofs alone. The act's
# number and its own proof ride either way: they are proof material about the
# act, not content the ends address.
# An IMPORTED link re-exports: the foreign bundle copied unchanged — it stays
# the authority for authorship and birth time, particles included if the
# sender attached them — plus this repo's custody layer appended under
# custody/<n>-<signer12>/. A custody layer is itself a proof bundle in the
# same layout, over the receipt instead of the record, so the same
# verification machinery covers both.

use _deps/ssh-sign.nu [ ssh-sign ]
use _deps/pubkey.nu [ pubkey ]
use _repo.nu graph-root
use _fs.nu [ list-files list-dirs copy-file copy-tree cwd-relative ]
use _layout.nu [
    particles-dir
    exports-dir
    certs-dir
    cert-path
    cert-filename
    link-path
    snapshot-dir
    imported-edge-copies
    receipt-relpath
    receipt-cert-path
    receipt-cert-filename
    order-path
    order-relpath
    order-cert-path
    order-cert-filename
    custody-dir
    custody-layer-dirname
    handoff-filename
]
use _validate.nu [ CID_V0_RE ]
use _record.nu [ read-link ]
use _receipt.nu [ read-receipt custody-layers ]
use _signer.nu [ own-signer ]
use _particle.nu [ particle-find ]
use _handoff.nu [ handoff-bytes HANDOFF_SCHEMA ]

# Copy one seal's verification artifacts into a proof dir: the snapshot's
# root statement + signatures, the signer pubkeys, and the OTS bundles
# committing to that root. Shared by the birth bundle and custody layers.
def assemble-seal-artifacts [root: path out: path root_hex: string]: nothing -> nothing {
    let snap = snapshot-dir $root $root_hex
    if not ($snap | path exists) {
        error make {msg: $"seal snapshot missing for root ($root_hex) — the proof predates the seals/ convention?"}
    }
    mkdir ($out | path join multiproofs pubkeys)
    # `for`, not `each`: a raise inside an `each` closure comes back as "Eval
    # block failed with pipeline input", so copy-file's message would be lost.
    # These are the root statement and its signatures — the files a dropped
    # copy would remove from the export while `assert-complete-bundle`, which
    # only counts root certificates, still called the bundle complete.
    for f in (list-files $snap) {
        copy-file $f ($out | path join multiproofs)
    }

    # Signer pubkeys, found by KEY MATERIAL. The middle segment of a sig name is
    # the signer's fingerprint (nu-multiproof's _sig.nu: `sig-path-for` names the
    # file after `signing-principal`, which is the key's own digest), while a
    # pubkey file's name is decoration — upstream pins that a key registered
    # under any name still signs and verifies. Joining the segment onto
    # `pubkeys/<name>.pub` therefore ships a bundle with no signer key at all
    # for any signer whose file is not named the way `init` names it.
    # Anchored regex, greedy middle: a fingerprint cannot contain ".sig", but
    # the bare `<file>.sig` form must not parse as one either.
    let signers = list-files $snap --suffix ".sig"
        | each { path basename | parse --regex '^tree-root\.txt\.(?<fp>.+)\.sig$' | get --optional 0.fp }
    let registered = list-files ($root | path join multiproofs pubkeys) --suffix ".pub"
        | each {|f| {path: $f fingerprint: (open --raw $f | pubkey fingerprint)} }
    let copied = $signers | each {|fp|
            let hit = $registered | where fingerprint == $fp
            if ($hit | is-empty) { null } else {
                copy-file ($hit | first | get path) ($out | path join multiproofs pubkeys)
                $fp
            }
        }
    if ($copied | is-empty) {
        error make {msg: "no signer pubkey found for the snapshot's signatures — the bundle could never verify"}
    }

    assemble-ots $root $out $root_hex
}

# OTS bundles committing to one root, matched by their frozen root statement.
# Plain content match — discovery only; verify re-checks the commitment
# cryptographically.
#
# One directory per seal, named after the root it stamped, so a bundle carrying
# two roots (a birth certificate and a position frozen under a later seal)
# keeps both here without a collision.
def assemble-ots [root: path out: path root_hex: string]: nothing -> nothing {
    let ots_bundles = list-dirs ($root | path join multiproofs ots-timestamps)
        | where ($it | path basename | str starts-with "tree-root.")
        | where {|d|
            let frozen = $d | path join tree-root.txt
            ($frozen | path exists) and (open --raw $frozen | str contains $root_hex)
        }
    if ($ots_bundles | is-empty) {
        print "note: no OTS bundle for this root (sealed with --no-stamp?) — the bundle's timestamp will report absent"
        return
    }
    mkdir ($out | path join multiproofs ots-timestamps)
    # `for`, not `each`, for the reason the two copies above give: a raise
    # inside an `each` closure comes back as "Eval block failed with
    # pipeline input". Measured here with one OTS file unreadable —
    # copy-tree caught the short copy, and those five words were the whole
    # message the operator got.
    for d in $ots_bundles {
        copy-tree $d ($out | path join multiproofs ots-timestamps ($d | path basename))
    }
}

# The link's position, its frozen proof, and the seal that proves it — at the
# same relative paths the graph home files them under, so one rule finds them
# in a bundle and in the repo.
#
# The seal artifacts go to `seals/<root12>/` and not into `multiproofs/`, ALWAYS,
# even when the position froze under the same root as the birth certificate.
# A backfilled position freezes under a later seal than the link it counts, so
# a bundle can carry two roots and `multiproofs/` holds one statement; keeping
# the position's own snapshot where the graph home keeps its snapshots is what
# lets verification look it up by one rule instead of branching on whether the
# two roots happen to coincide. What it costs when they do is a second copy of
# two small files.
def assemble-position [root: path out: path signer: string edge_cid: string birth_root: string]: nothing -> nothing {
    let cert = order-cert-path $root $signer $edge_cid
    if not ($cert | path exists) {
        error make {msg: $"no frozen position proof for ($signer)'s ($edge_cid) — run `nu-cybergraph seal` first, then export: a number no seal has catalogued is provable to nobody"}
    }
    let relpath = order-relpath $signer $edge_cid
    mkdir ($out | path join ($relpath | path dirname))
    copy-file (order-path $root $signer $edge_cid) ($out | path join $relpath)
    copy-file $cert ($out | path join ($relpath | path dirname) (order-cert-filename $edge_cid))

    let proof = open --raw $cert | from json
    let snap = snapshot-dir $root $proof.root
    if not ($snap | path exists) {
        error make {msg: $"seal snapshot missing for root ($proof.root) — the position proof predates the seals/ convention?"}
    }
    let dest = snapshot-dir $out $proof.root
    mkdir $dest
    for f in (list-files $snap) {
        copy-file $f $dest
    }
    # Only when the two roots differ: the birth assembly has already copied
    # this root's stamp archive, and it is keyed by root, so a second pass
    # would land on a directory that is already there.
    if $proof.root != $birth_root {
        assemble-ots $root $out $proof.root
    }
}

# Copy the particle files a link record's two ends address, for whichever of
# them this repo actually holds a file for. cid_from is always the preimage
# of the record's instruction; cid_to is one too for edges that name a
# particle rather than another link (an "about" edge names a link CID
# instead, and `particle-find` then just returns nothing — trying both ends
# uniformly is simpler than asking each verb which of its fields is which).
def assemble-particles [root: path out: path rec: record]: nothing -> nothing {
    for cid in ([$rec.cid_from $rec.cid_to] | uniq) {
        let file = particle-find $root $cid --optional
        if $file != null {
            mkdir (particles-dir $out)
            copy-file $file (particles-dir $out)
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
# rules — `ssh-sign sign` -> `signing-principal` in nu-multiproof's _key-helpers.nu, "a
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
def write-handoff [root: path dir: path edge_cid: string act: record to: string receipt_hash: any key: path]: nothing -> nothing {
    let handoff = {
        schema: $HANDOFF_SCHEMA
        cid_from: $act.cid_from
        cid_to: $act.cid_to
        signer: $act.signer
        from: (own-signer $root --key $key)
        to: $to
        receipt: $receipt_hash
        handed_at: (date now | format date "%+")
    }
    let file = $dir | path join (handoff-filename $edge_cid)
    handoff-bytes $handoff | save --raw $file
    # `ignore`: upstream hands back the .sig path, which no caller reads — and
    # dropping it is what lets every writer in this file share one contract,
    # `nothing -> nothing`, instead of one of them leaking a value into
    # assemble-bundle's return type.
    ssh-sign sign $file --key $key --pubkeys-dir ($root | path join multiproofs pubkeys) | ignore
}

# The writer's own exit check — the same root-cert test import runs first.
# Observed once: an interior `cp -r` error was printed but not raised, and a
# custody re-export shipped with the birth bundle missing entirely, exit 0.
# Whatever the cause, a partial bundle must not leave the repo with exit 0.
# Removing it is main's job, not this one's: every failure below the "already
# exists" check leaves the same debris, so one cleanup covers them all.
def assert-complete-bundle [out: path]: nothing -> nothing {
    let certs = list-files $out --suffix ".cert.json"
    if ($certs | length) != 1 {
        error make {msg: $"bundle came out incomplete: ($certs | length) *.cert.json at the root instead of 1 — partial bundle removed, re-run the export"}
    }
}

# Everything that writes into the destination dir. Split out of main so the
# whole of it sits under one cleanup: from here down, any raise leaves debris.
# `resolved` is main's answer to which copy of the edge leaves: {own: bool,
# signer: cid, dir: the imported bundle for a foreign act, null for an own one}.
def assemble-bundle [root: path out: path edge_cid: string resolved: record act: record to: any key: any links_only: bool]: nothing -> nothing {
    if $resolved.own {
        # Own act: the birth bundle, mirroring the graph's own layout — the
        # leaf path `<signer>/<edge>.json` is what the certificate proves.
        let cert = cert-path $root $resolved.signer $edge_cid
        let proof = open --raw $cert | from json
        let record_file = $root | path join $proof.leaf.filepath
        mkdir ($out | path join ($proof.leaf.filepath | path dirname))
        copy-file $record_file ($out | path join $proof.leaf.filepath)
        copy-file $cert ($out | path join (cert-filename $edge_cid))
        assemble-seal-artifacts $root $out $proof.root
        assemble-position $root $out $resolved.signer $edge_cid $proof.root
        if not $links_only {
            assemble-particles $root $out (read-link $record_file)
        }
        if $to != null {
            # The author has no receipt — their handoff pins nothing but the link
            write-handoff $root $out $edge_cid $act $to null $key
        }
        return
    }

    # Imported act: re-export with this repo's custody layer appended. Paths
    # go by (author, edge) — the mirrored layout — while the receipt and the
    # handoff inside state the act's three components (see _verify-helpers.nu).
    let author = $resolved.signer
    let rcert = receipt-cert-path $root $author $edge_cid
    if not ($rcert | path exists) {
        error make {msg: $"no frozen receipt proof for ($author)'s ($edge_cid) — run `nu-cybergraph seal` after import, then re-export"}
    }
    copy-tree $resolved.dir $out

    let receipt_relpath = receipt-relpath $author $edge_cid
    let receipt = read-receipt ($root | path join $receipt_relpath)
    let index = (custody-layers $out | length) + 1
    let layer = custody-dir $out | path join (custody-layer-dirname $index $receipt.custodian)
    let proof = open --raw $rcert | from json
    mkdir ($layer | path join ($receipt_relpath | path dirname))
    copy-file ($root | path join $receipt_relpath) ($layer | path join $receipt_relpath)
    copy-file $rcert ($layer | path join (receipt-cert-filename $edge_cid))
    assemble-seal-artifacts $root $layer $proof.root
    if $to != null {
        # A custodian's handoff pins their receipt — the exact chain state handed over
        let receipt_hash = open --raw ($root | path join $receipt_relpath) | hash sha256
        write-handoff $root $layer $edge_cid $act $to $receipt_hash $key
    }
}

# Export one act over an edge as a portable, offline-verifiable bundle: the
# birth bundle for an own act; for an imported one, the foreign bundle
# unchanged plus this repo's custody layer. --to names the recipient in a
# signed handoff.
export def main [
    edge_cid: string # Edge CID: authored here (certs/) or imported (imported/*/)
    --repo: path # Source repo root (default: git root of current directory)
    --out: path # Bundle destination (default: exports/<signer>/<edge-cid>)
    --to: string # Recipient signer CID — adds a signed handoff (default: none, an open export)
    --signer: string # Whose act to export, when more than one signer holds this edge
    --key: path # SSH private key for the handoff signature (default: from git config user.signingKey)
    --links-only # own act only: without particles — the record, its certificate and its position with their proofs (no-op re-exporting an imported act — its particles, if any, are the sender's foreign bytes, copied unchanged either way)
]: nothing -> path {
    let root = graph-root $repo
    if $to != null and $to !~ $CID_V0_RE {
        error make {msg: $"--to must be a signer CID \(base58btc CID v0\): ($to)"}
    }
    let key = if $to == null { null } else { resolve-handoff-key $root $key }

    # Which copy of the edge leaves: an own act (a birth certificate under
    # certs/<signer>/) wins over imported ones, as the certificate lookup did
    # when the argument named the act directly. More than one candidate is a
    # question only the caller can answer — refused, never guessed.
    let own_hits = list-dirs (certs-dir $root)
        | each { path basename }
        | where {|s| $signer == null or $s == $signer }
        | where ((cert-path $root $it $edge_cid) | path exists)
    let imported_hits = if ($own_hits | is-empty) {
        imported-edge-copies $root $edge_cid | where {|h| $signer == null or $h.signer == $signer }
    } else { [] }
    if ($own_hits | is-empty) and ($imported_hits | is-empty) {
        error make {msg: $"unknown edge: ($edge_cid) — no birth certificate in certs/ and nothing in imported/"}
    }
    if ($own_hits | length) > 1 {
        error make {msg: $"several signers hold a birth certificate for ($edge_cid): ($own_hits | str join ', ') — pass --signer"}
    }
    if ($imported_hits | length) > 1 {
        error make {msg: $"several imported signers hold ($edge_cid): ($imported_hits | get signer | str join ', ') — pass --signer"}
    }
    let resolved = if ($own_hits | is-not-empty) {
        {own: true signer: ($own_hits | first) dir: null}
    } else {
        {own: false signer: $imported_hits.0.signer dir: $imported_hits.0.dir}
    }

    # exports/ mirrors the layout too — signer above, edge below — so two
    # signers' exports of one edge cannot collide.
    let record_root = if $resolved.own { $root } else { $resolved.dir }
    let act = read-link (link-path $record_root $resolved.signer $edge_cid)
    let out = if $out != null { $out | path expand } else { exports-dir $root | path join $resolved.signer $edge_cid }
    if ($out | path exists) {
        error make {msg: $"bundle destination already exists: ($out)"}
    }
    mkdir ($out | path dirname)

    # Why a cleanup and not more pre-checks: a raise below this line — an
    # unregistered signing key most of all (see resolve-handoff-key) — leaves a
    # complete-looking bundle whose handoff is unsigned, and the retry then hits
    # "bundle destination already exists" above. The dir did not exist
    # before, so removing it restores exactly the state the export started in,
    # for every cause rather than the one a pre-check could name. The error is
    # re-raised raw: labels, help and location are the operator's evidence.
    try {
        assemble-bundle $root $out $edge_cid $resolved $act $to $key $links_only
        assert-complete-bundle $out
    } catch {|e|
        rm --recursive --force $out
        error make $e.raw
    }
    $out | cwd-relative
}
