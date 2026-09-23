# Create link records in a signer's repo, and read the graph they make.

use _repo.nu graph-root
use _record.nu [ link-cid edge-bytes edge-cid read-link ]
use _layout.nu [ signer-dir link-path imported-dir order-dir order-path ]
use _order.nu [ write-added-at ]
use _particle.nu [ resolve-particle store-index ]
use _signer.nu [ resolve-signer ]
use _read.nu [ read-links deref touches ]
use _validate.nu [ CID_V0_RE ]
use _fs.nu [ list-dirs cwd-relative ]

# Write a new link: the pair {cid_from, cid_to} to <signer>/<edge-cid>.json,
# the file named by its own content address, the signer by its directory.
# An endpoint is any particle; its CID is the CID v0 of its bytes.
# Both endpoints accept a CID or content: a non-CID argument is resolved to
# bytes (a path is opened, anything else is literal — see resolve-arg-bytes)
# and published as a file under particles/, its CID linked (see _particle.nu).
# `--signer` publishes content too, but by a narrower rule (see resolve-signer):
# it never opens a path, and a CID there is never checked against particles/.
# Idempotent: asserting the same triple again returns the existing record,
# not an error. A CID endpoint must resolve to a file this repo holds — see
# resolve-particle for why, and --allow-missing for the escape hatch to name a
# CID whose bytes this repo does not (yet) hold.
@example "link two particles by the CIDs of their bytes" { link add QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp --allow-missing }
@example "publish two texts as particles and link them" { link add "cyber" "bostrom" }
@example "link a file to text, by its path" { link add path/to/doc.md "reviewed" }
@example "sign under an ad-hoc identity, published as a particle" { link add "cyber" "bostrom" --signer alice }
export def add [
    cid_from: string # source vertex: a CID v0, a path to publish, or content to publish as a particle
    cid_to: string # target vertex: a CID v0, a path to publish, or content to publish as a particle
    --signer: string # signer: a CID v0, or content published as a particle — never a path (default: this repo's own identity, the key it signs with)
    --repo: path # Target repo root (default: git root of current directory)
    --allow-missing # skip the local-file check on a CID endpoint (see resolve-particle)
    --literal # treat a text endpoint as literal content even if it names a path
]: nothing -> record {
    let root = graph-root $repo
    # Why the signer is resolved before the endpoints: `resolve-particle`
    # PUBLISHES a content endpoint under particles/. Resolved inside the record
    # below, `own-signer` ran last, so a repo with no single signer identity had
    # already written files by the time it raised — side effects before the
    # check that forbids them, and the operator was left with orphan particles
    # for a link that was never written.
    let signer_cid = resolve-signer $root $signer
    let index = store-index $root
    let pair = {
        cid_from: (resolve-particle $root $index $cid_from --allow-missing=$allow_missing --literal=$literal)
        cid_to: (resolve-particle $root $index $cid_to --allow-missing=$allow_missing --literal=$literal)
    }
    let rec = $pair | insert signer $signer_cid
    # Both addresses are DERIVED, never published. `particles/` holds bytes a
    # writer decided to put there, not bytes this command computed on the
    # way — so the only files `link add` writes to the store are the ones its
    # endpoints resolved to.
    #
    # What that costs: stating something about the edge just made
    # (`link add A <edge>`) is two steps — `particle add-edge` puts the
    # pair record in the store, then its CID can be named. The bytes that
    # writes are byte-identical to this link file, which looks like a copy;
    # the difference is that a writer decided on it,
    # for a reference they are about to make. It is also what keeps
    # `link touching` whole: its walk upward reaches an edge through a store
    # file, and that file is there whenever someone meant to point at it.
    #
    # Not solved by resolving an edge CID out of the link file instead: that
    # buys one step at the price of a second index beside the store, and speed
    # is not an argument here (CLAUDE.md, "An academic prototype, not a
    # product").
    let edge = edge-cid $pair
    mkdir (signer-dir $root $signer_cid)
    let out = link-path $root $signer_cid $edge
    # The path IS the triple — signer in the directory, edge in the filename —
    # so file existence IS the triple guard: one act, one address, one file —
    # mirroring bostrom's consensus, which rejected a repeat cyberlink. Why no
    # --reassert: a repeat is byte-identical, so there is nothing new to store;
    # re-assertion over time is a statement ABOUT the act (e.g. `convention
    # claimed-at`), not a second copy of it.
    #
    # Why a no-op and not an error: a repeat is the same act by the same
    # triple-guard argument above, and an agent replaying a run interrupted
    # mid-way has no way to tell "already done" from "rejected" except by
    # re-deriving the CID itself first. The guard already makes a repeat
    # harmless on disk; erroring on it only pushed that work onto the caller.
    # `read-link` re-checks self-addressing and canonical form before the
    # no-op returns — a file at this path that fails either is not "already
    # asserted", it is a corrupted store, and that must fail loud here rather
    # than be reported as a successful repeat.
    if ($out | path exists) {
        read-link $out | ignore
    } else {
        edge-bytes $pair | save --raw $out
        # The position is written on the SAME branch that writes the record, so
        # the two exist together or not at all: a link with no position is what
        # `seal` refuses on, and a position with no link is the same refusal
        # read the other way. The repeat above writes neither — the triple
        # guard already says the act is on disk, and a second position for one
        # act would be a second act.
        #
        # A TIME and not a number, and no walk over `order/` to find the
        # highest one: numbering needs a moment that sees the whole run at
        # once, and this is not it — the seal is (_order.nu says why). What
        # this branch records is arrival, which is the whole reason to write
        # anything here, and a clock answers that without reading a run.
        #
        # After the record, not before: the position counts an act, so a
        # failure between the two leaves a record with no position — visible,
        # refused by the next seal, and repaired by removing the record and
        # adding it again — rather than a position counting nothing.
        mkdir (order-dir $root | path join $signer_cid)
        write-added-at (order-path $root $signer_cid $edge) (date now)
    }
    # No position here either, in any shape. There is no number to report —
    # none exists until a seal numbers the run — and the claimed time is
    # scaffolding the seal deletes, so a column for it reports something the
    # graph never keeps: null on a repeat of an already-sealed act, a time on
    # a fresh one. `nu-cybergraph order list` is the reading of the run.
    #
    # No link_cid: `edge_cid` addresses the file just written, but the
    # cyberlink's derived CID addresses nothing until someone publishes its
    # preimage (`particle add-link`) — and reporting a non-address beside an
    # address invites treating them alike. `record` carries all three
    # components, so a caller who wants it computes it.
    {edge_cid: $edge path: ($out | cwd-relative) record: $rec}
}

# One link, read: both addresses, the triple, then what its endpoints say.
# The one place the decoding rule lives, so `list` and `touching` cannot
# drift.
def statement [index: record l: record]: nothing -> record {
    let src = deref $index $l.cid_from
    {
        edge_cid: $l.edge_cid
        link_cid: $l.link_cid
        cid_from: $l.cid_from
        cid_to: $l.cid_to
        signer: $l.signer
        op: (if $src == null { null } else { $src | get --optional op })
        src: $src
        tgt: (deref $index $l.cid_to)
    }
}

# The whole local graph as a table, one row per link record: the triple as
# stored, then what it says. `op` is the verb the source record declares — null
# for a plain edge, which is not a lesser thing: "this root publishes this file"
# needs no verb. `src` and `tgt` are the endpoints' own records where the store
# holds them, so the operands a convention hid behind a derived CID are back in
# the open.
#
# Own links only (the signer directories at the graph root). An imported
# bundle is another signer's copy, checked
# by `verify` against its birth seal, and mixing it in here would silently turn
# a reading of what THIS signer said into a reading of everyone — the exact
# distinction aggregation rests on.
@example "every edge update with the record that states it" { link list | where op == "update_edge" | select link_cid src cid_to }
export def list [
    --repo: path # Repo root (default: git root of current directory)
]: nothing -> table {
    let root = graph-root $repo
    let index = store-index $root
    read-links $root | each {|l| statement $index $l }
}

# Every link a landed import carries, one row per bundle under imported/,
# decoded the same way `list` decodes its own graph — read-link's
# self-address and canonical-form check, then operands dereferenced against
# JUST that bundle's own particles/. A bundle is an island: `bundle` attaches
# the ends' particles when the exporter held them (see its own doc comment),
# so most edges decode fully from the bundle alone; this never reaches into
# this repo's own particles/, which would blur "what the bundle proves" with
# "what this repo separately happens to know" too.
#
# The companion reader to `list`'s own-links-only boundary above: `signer`
# names whose claim a row is, and aggregating across signers — consensus,
# tallies, dedup — is a reading policy for the caller to build on this
# primitive, same as `tally` never sums across positions.
@example "every link a landed bundle carries" { link imported }
@example "what one signer said, decoded" { link imported | where signer == QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr }
export def imported [
    --repo: path # Repo root (default: git root of current directory)
]: nothing -> table {
    let root = graph-root $repo
    list-dirs (imported-dir $root)
    | each {|signer_dir| list-dirs $signer_dir }
    | flatten
    | each {|bundle|
        let index = store-index $bundle
        read-links $bundle | each {|l| statement $index $l }
    }
    | flatten
    | sort-by link_cid
}

# Every link that names this CID, one row per place it is named — bj003's
# primitive: given a CID, which edges touch it.
#
# `role` is where it sits: `cid_from`, `cid_to` or `signer` for the record's
# own fields, `cid_from.about` for an operand inside an instruction's source
# record, `cid_to.cid_from` for a field of the edge a `confirm-edge` speaks about.
# The distinction is the whole answer: as `cid_to` of an `update_particle` the
# particle is the new version, as `cid_from.about` it is the replaced one. A link that names
# the CID twice returns twice — one act stating the same address in two
# positions is a fact about the act, not a duplicate to be swept up.
#
# The walk goes upward from the CID, over the files that name it, so a query
# costs the neighbourhood and not the graph. `--scan` reads every record
# instead of asking `rg` to narrow the candidates first; same rows, and the
# tests pin that equality.
@example "everything said about a particle" { link touching QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV }
export def touching [
    cid: string # CID v0 of the particle or record the statements are about
    --repo: path # Repo root (default: git root of current directory)
    --scan # read every record instead of narrowing with rg (same answer, slower)
]: nothing -> table {
    if $cid !~ $CID_V0_RE {
        error make {msg: $"not a CID v0: ($cid) — link touching takes the bare 46-char CID"}
    }
    let root = graph-root $repo
    let hits = touches $root $cid --scan=$scan
    if ($hits | is-empty) { return [] }
    let index = store-index $root
    $hits
    | sort-by file role
    | each {|h|
        let rec = read-link $h.file
        statement $index ({edge_cid: ($h.file | path parse | get stem) link_cid: (link-cid $rec)} | merge $rec)
        | insert role $h.role
        | move role --after link_cid
    }
}

# Count what the graph says about a CID: one row per (verb, position), with the
# links that say it and the distinct signers who signed them.
#
# Why counts per row and never a total: bj002 keeps repetition and confirmation
# apart — repeating an edge claims you did the work yourself, confirming leans
# on whoever did — so a reader reports two numbers, never their sum. The same
# holds across positions: `deny-edge` of an edge and `deny-link` of one signer's
# cyberlink are different statements. Summing is a reading policy, and a
# reading policy belongs to the reader, not to the command that counts.
#
# `signers` is the honest limit of a local graph: one repo is one signer, so
# it reads 1 until imported links are counted too. The column is here because
# it is the number a weighing formula needs, and because a reader must see that
# ten links from one signer are not ten voices.
@example "how the graph speaks about a particle" { link tally QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV }
export def tally [
    cid: string # CID v0 of the particle or record the statements are about
    --repo: path # Repo root (default: git root of current directory)
    --scan # read every record instead of narrowing with rg (same answer, slower)
]: nothing -> table {
    touching $cid --repo $repo --scan=$scan
    | group-by {|r| [($r.op | default "—") $r.role] | to json --raw }
    | items {|_ rows|
        {
            op: ($rows | first | get op)
            role: ($rows | first | get role)
            links: ($rows | get link_cid | uniq | length)
            signers: ($rows | get signer | uniq | length)
        }
    }
    | sort-by op role
}
