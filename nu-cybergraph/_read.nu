# Reading the graph — bj002 «Чтение инструкций» / "Reading instructions".
#
# A CID is opaque, so the edge X → Y does not show that X is an instruction.
# What makes it readable is that every convention publishes the record it
# minted (convention.nu `address`): the source is its own preimage, so
# dereferencing it gives the named fields back with the real operand CIDs. That
# is the second of the two ways bj002 names. The first — derive the candidate
# addresses of everything already seen and match them against `cid_from` —
# needs no store but needs a set of candidates; this one needs the store and no
# candidates, which is what a reader of somebody else's graph has.
#
# What dereferencing cannot do is settle the question in general, and bj002
# says so in the same paragraph: an instruction record is an ordinary published
# file, so anything published in that shape answers this test. A reader gets
# "this parses as an instruction", never "this was meant as one".

use _layout.nu [ signer-dirs link-files particles-dir store-cid ]
use _particle.nu [ index-find particle-verify store-index ]
use _record.nu [ read-link link-cid EDGE_KEYS ]
use _validate.nu [ CID_V0_RE ]
use _fs.nu list-files

# Every link in the graph home, walked over the signer directories, each
# checked against its own address by read-link. A row carries both addresses:
# the edge (the filename) and the cyberlink's derived CID, recomputed the way
# every reader now gets it — pair from the file, signer from the path. Sorted
# by path (signer, then edge) so a reading is reproducible across filesystems.
export def read-links [root: path]: nothing -> table {
    link-files $root
    | sort-by file
    | each {|l|
        let rec = read-link $l.file
        {edge_cid: $l.edge link_cid: (link-cid $rec)} | merge $rec
    }
}

# The record a store file publishes, or null when it is not an instruction
# preimage: not JSON, not a JSON object, or an object with a non-string value.
# The last is the format's own line (_derive.nu: a canonical record is flat,
# values are strings, a reference to another record is its CID), and drawing it
# here is what keeps ordinary published data out of the reading — an RFC 3339
# timestamp file parses as a JSON scalar, and without the flatness rule a
# nested JSON document would come back as a fake instruction with fake
# operands.
def deref-file [file: path cid: string]: nothing -> any {
    # Verified outside the `try`: the catch is for "these bytes are not JSON",
    # and a tampered file must not reach a reader disguised as that.
    let bytes = particle-verify $file $cid
    # `into binary | decode utf-8` and not a bare `decode`: `open --raw` hands
    # back a string for text and a binary for anything else, so the round trip
    # is what makes one code path out of two input types. It is lossless here
    # because particle-verify hashed those same bytes back to this CID first.
    let parsed = try { $bytes | into binary | decode utf-8 | from json } catch { null }
    if not ($parsed | describe | str starts-with "record") { return null }
    if not ($parsed | values | all {|v| ($v | describe) == "string" }) { return null }
    $parsed
}

# The same, addressed by CID through the store index the reader built once
# (_particle.nu store-index). Null also when this repo holds no file for the
# CID — legitimate, a cyberlink names CIDs and the bytes need not be local.
export def deref [index: record cid: string]: nothing -> any {
    let file = index-find $index $cid --optional
    if $file == null { return null }
    deref-file $file $cid
}

# Files that could name this CID: everything under the signer directories and
# particles/, narrowed by a text search when `rg` is on PATH. bj002 names the search
# itself — an operand's CID is a literal string in every record that mentions
# it, so `rg` finds the whole neighbourhood of a vertex without reading the
# graph. It is only a narrowing: a file that does not contain the string cannot
# name the CID, so dropping it changes nothing, and every file that survives is
# read and checked exactly as it would have been. `--scan` forces the full read
# — the same answer, slower — and the tests run both ways against each other,
# because an optional fast path that nothing exercises is a path that rots.
#
# The two rg flags are correctness, not taste: `--no-config` so a user's
# RIPGREP_CONFIG_PATH cannot add an exclusion, `--no-ignore` so a gitignored
# graph home is still searched. Anything rg silently omits is a link a reader
# would never see. Nothing here compensates for rg listing a file the scan
# would not (it recurses into subdirectories) or the other way round (`ls`
# without --all hides a dotfile): both sides are filtered by the graph's own
# filename rules in `touches`, which is where the two are made to agree.
export def candidates [root: path cid: string --scan]: nothing -> list<path> {
    let dirs = (signer-dirs $root) ++ ([(particles-dir $root)] | where ($it | path exists))
    if ($dirs | is-empty) { return [] }
    if $scan or (which rg | is-empty) {
        return ($dirs | each {|d| list-files $d } | flatten)
    }
    let found = ^rg --no-config --no-ignore --fixed-strings --files-with-matches -- $cid ...$dirs | complete
    match $found.exit_code {
        0 => { $found.stdout | lines | where $it != "" }
        1 => { [] } # rg's "no matches", not a failure
        _ => { error make {msg: $"rg failed over the graph home: ($found.stderr | str trim)"} }
    }
}

# Which links name this CID, and where — walked upward from the CID instead of
# downward from every link, so the work is proportional to the neighbourhood
# and not to the graph.
#
# Three ways a link can name it. By path: the signer lives in the directory
# name, not in the bytes — so no text search can narrow that case, and every
# link in the signer's own directory names them; this is what keeps a
# signer's own work countable. Directly: the CID stands in the pair, as
# `cid_from` or `cid_to`. Indirectly: an instruction preimage names it as an
# operand, and the link names that record; then the role is the endpoint's
# key, a dot, and the field inside — `cid_from.about`. The record may itself
# be an operand of a bigger record (`answer` is that shape), so the step
# repeats, and the role grows one field per level.
#
# A candidate is kept only if it is a file of the graph by the graph's own
# rules: a file link-files walks (seal's rule, so a reading and a seal
# catalogue the same set) or a store name that parses as an address. That
# filter is what makes the search and the scan agree — rg recurses into
# subdirectories and sees dotfiles, a listing does neither, and neither of
# those is a graph file. The `op` key needs no exclusion here: its value is a
# verb the format defines, and `touching` accepts nothing but a CID v0.
#
# The rows return the FILE, not a bare stem: the stem alone is the edge, and
# reconstructing the act needs the signer half of the path too.
export def touches [root: path cid: string --scan]: nothing -> table {
    let links = link-files $root
    let signed = $links | where signer == $cid | each {|l| {file: $l.file role: "signer"} }

    let seeds = candidates $root $cid --scan=$scan
    let link_paths = $links | get file

    # EDGE_KEYS and not the read-back record's columns: read-link returns the
    # triple (signer inserted from the path), and matching that field here
    # would double the by-path rows above — but only under --scan, since rg
    # never surfaces a file whose bytes hold nothing. The scan and the search
    # must agree, so the field set is pinned to what the bytes hold.
    let direct = $seeds
        | where ($it in $link_paths)
        | each {|f|
            let rec = read-link $f
            $EDGE_KEYS
            | where (($rec | get $it) == $cid)
            | each {|key| {file: $f role: $key} }
        }
        | flatten

    let indirect = $seeds
        | where (($it | path dirname) == (particles-dir $root) and (store-cid $it) != null)
        | each {|f|
            let record_cid = store-cid $f
            let rec = deref-file $f $record_cid
            if $rec == null { [] } else {
                $rec
                | columns
                | where (($rec | get $it) == $cid)
                | each {|key|
                    touches $root $record_cid --scan=$scan
                    | each {|row| {file: $row.file role: (role-path $row.role $key)} }
                }
                | flatten
            }
        }
        | flatten

    $signed ++ $direct ++ $indirect
}

# Where a CID sits, as one dotted string: the endpoint's own key, then the
# fields walked to reach it.
def role-path [prefix: string path: string]: nothing -> string {
    if $path == "" { $prefix } else { $"($prefix).($path)" }
}

# Every CID this graph's own links name — the set a store file has to fall in
# for the graph to reach its bytes at all. The question `particle uncommitted` and
# the seal guard both ask, and the reason it is answered downward from the links
# rather than upward from each file: `touches` costs one `rg` over the graph per
# CID, which is the right shape for one vertex and the wrong one for a sweep of
# the whole store.
#
# Five seeds per link, not the pair's two. The signer is named by the path, and
# a signer published as a particle (`link add --signer alice`) has its bytes in
# the store like any endpoint. The other two are the link's derived addresses,
# the pair and the triple. `link add` publishes neither, but a convention
# minting one as its target does, and so does `particle add-edge`/`add-link`
# run ahead of a reference — and those bytes are then as reachable as an
# endpoint. Without the seeds a convention's own target
# record would sweep up as an orphan, which `stageable` never stages, so it
# would silently miss every root.
#
# Then the step `touches` walks upward, walked downward: an instruction preimage
# names its operands as CIDs, so dereferencing a seed adds them, and the
# expansion repeats until a round finds nothing new. The fixpoint is what ends
# it, not a depth limit — a cycle would need a record containing the hash of
# bytes that contain it, so it is not constructible.
export def reachable-cids [root: path]: nothing -> list<string> {
    let index = store-index $root
    let seeds = read-links $root
        | each {|l| [$l.cid_from $l.cid_to $l.signer $l.edge_cid $l.link_cid] }
        | flatten
        | uniq
    mut seen = []
    mut frontier = $seeds
    while ($frontier | is-not-empty) {
        $seen = ($seen ++ $frontier | uniq)
        # `deref` returns null for a CID whose bytes are not local and for one
        # whose file is not an instruction preimage — both are ordinary, and
        # both simply add no operands.
        $frontier = $frontier
            | each {|cid| deref $index $cid | default {} | values }
            | flatten
            | where $it =~ $CID_V0_RE
            | uniq
            | where $it not-in $seen
    }
    $seen
}
