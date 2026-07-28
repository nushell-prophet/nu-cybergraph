# Create link records in a signer's repo, and read the graph they make.

use _repo.nu graph-root
use _record.nu [link-bytes link-cid]
use _layout.nu [links-dir link-path]
use _particle.nu [resolve-particle store-index]
use _signer.nu [own-signer]
use _read.nu [read-links deref record-mentions role-path]
use _validate.nu [CID_V0_RE]

# Write a new link record to links/<cid>.json, named by its own content address.
# An endpoint is any content-addressed file; its CID is the CID v0 of its bytes.
# Both endpoints accept a CID or content: a non-CID argument is published as a
# file under particles/ and its CID is linked (see _particle.nu).
@example "link two files by the CIDs of their bytes" { link add QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp }
@example "publish two texts as files and link them" { link add "cyber" "bostrom" }
export def add [
    cid_from: string # source vertex: a CID v0, or content to publish as a file
    cid_to: string # target vertex: a CID v0, or content to publish as a file
    --signer: string # Signer CID (default: CID of the single registered pubkey)
    --repo: path # Target repo root (default: git root of current directory)
]: nothing -> record {
    let root = graph-root $repo
    let rec = {
        cid_from: (resolve-particle $root $cid_from)
        cid_to: (resolve-particle $root $cid_to)
        signer: (if $signer != null { $signer } else { own-signer $root })
    }
    let cid = link-cid $rec
    mkdir (links-dir $root)
    let out = link-path $root $cid
    # The record IS the triple, so file existence IS the triple guard: one act,
    # one CID, one file — mirroring bostrom's consensus, which rejected a repeat
    # cyberlink. Why no --reassert: a repeat is byte-identical, so there is
    # nothing new to store; re-assertion over time is a statement ABOUT the act
    # (e.g. `convention claimed-at`), not a second copy of it.
    if ($out | path exists) {
        error make {msg: $"signer already asserted this edge: ($cid)"}
    }
    link-bytes $rec | save --raw $out
    {cid: $cid path: $out record: $rec}
}

# One pass over the graph: every link, what its endpoints say, and every CID
# they name. `list` and `touching` are two views of this one table, so the
# dereferencing rule lives in one place.
def statements [root: path]: nothing -> table {
    let index = store-index $root
    read-links $root | each {|l|
        let src = deref $index $l.cid_from
        let tgt = deref $index $l.cid_to
        {
            cid: $l.cid
            cid_from: $l.cid_from
            cid_to: $l.cid_to
            signer: $l.signer
            op: (if $src == null { null } else { $src | get --optional op })
            src: $src
            tgt: $tgt
            names: (
                [{cid: $l.cid_from role: "cid_from"} {cid: $l.cid_to role: "cid_to"}]
                ++ (operands $index $src "cid_from")
                ++ (operands $index $tgt "cid_to")
            )
        }
    }
}

# The CIDs an endpoint's record names, each labelled by the endpoint it hangs
# off: `cid_from.about`, `cid_to.cid_from`. Null record — a plain endpoint —
# names nothing beyond itself.
def operands [index: record rec: any prefix: string]: nothing -> table {
    if $rec == null { return [] }
    record-mentions $index $rec | each {|m| {cid: $m.cid role: (role-path $prefix $m.path)} }
}

# The whole local graph as a table, one row per link record: the triple as
# stored, then what it says. `op` is the verb the source record declares — null
# for a plain edge, which is not a lesser thing: "this root publishes this file"
# needs no verb. `src` and `tgt` are the endpoints' own records where the store
# holds them, so the operands a convention hid behind a derived CID are back in
# the open.
#
# Own links only (links/). An imported bundle is another signer's copy, checked
# by `verify` against its birth seal, and mixing it in here would silently turn
# a reading of what THIS signer said into a reading of everyone — the exact
# distinction aggregation rests on.
@example "every update edge with the record that states it" { link list | where op == "update" | select cid src cid_to }
export def list [
    --repo: path # Repo root (default: git root of current directory)
]: nothing -> table {
    statements (graph-root $repo) | reject names
}

# Every link that names this CID, one row per place it is named — bj003's
# primitive: given a CID, which edges touch it.
#
# `role` is where it sits: `cid_from` or `cid_to` for an endpoint of the edge
# itself, `cid_from.about` for an operand inside an instruction's source
# record, `cid_to.cid_from` for a field of the edge a `confirm` speaks about.
# The distinction is the whole answer: as `cid_to` of an update the file is the
# new version, as `cid_from.about` it is the replaced one. A link that names
# the CID twice returns twice — one act stating the same address in two
# positions is a fact about the act, not a duplicate to be swept up.
@example "everything said about a file" { link touching QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV }
export def touching [
    cid: string # CID v0 of the file or record the statements are about
    --repo: path # Repo root (default: git root of current directory)
]: nothing -> table {
    if $cid !~ $CID_V0_RE {
        error make {msg: $"not a CID v0: ($cid) — link touching takes the bare 46-char CID"}
    }
    statements (graph-root $repo)
    | each {|s| $s.names | where cid == $cid | each {|n| $s | reject names | insert role $n.role | move role --after cid } }
    | flatten
}

# Count what the graph says about a CID: one row per (verb, position), with the
# links that say it and the distinct signers who signed them.
#
# Why counts per row and never a total: bj002 keeps repetition and confirmation
# apart — repeating an edge claims you did the work yourself, confirming leans
# on whoever did — so a reader reports two numbers, never their sum. The same
# holds across positions: `deny` of an edge and `deny` of one signer's
# cyberlink are different statements. Summing is a reading policy, and a
# reading policy belongs to the reader, not to the command that counts.
#
# `signers` is the honest limit of a local graph: one repo is one signer, so
# it reads 1 until imported links are counted too. The column is here because
# it is the number a weighing formula needs, and because a reader must see that
# ten links from one signer are not ten voices.
@example "how the graph speaks about a file" { link tally QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV }
export def tally [
    cid: string # CID v0 of the file or record the statements are about
    --repo: path # Repo root (default: git root of current directory)
]: nothing -> table {
    touching $cid --repo $repo
    | group-by {|r| [($r.op | default "—") $r.role] | to json --raw }
    | items {|_ rows| {
        op: ($rows | first | get op)
        role: ($rows | first | get role)
        links: ($rows | get cid | uniq | length)
        signers: ($rows | get signer | uniq | length)
    } }
    | sort-by op role
}
