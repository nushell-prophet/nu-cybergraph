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

use _layout.nu [links-dir particles-dir]
use _particle.nu [index-find particle-verify]
use _record.nu [read-link]

# Every link record in the graph home, each checked against its own address by
# read-link. Sorted by CID so a reading is reproducible across filesystems.
export def read-links [root: path]: nothing -> table {
    let dir = links-dir $root
    if not ($dir | path exists) { return [] }
    ls $dir | get name | sort | each {|f| {cid: ($f | path parse | get stem)} | merge (read-link $f) }
}

# The record a store file publishes, or null when it is not an instruction
# preimage: not JSON, not a JSON object, or an object with a non-string value.
# The last is the format's own line (_derive.nu: a canonical record is flat,
# values are strings, a reference to another record is its CID), and drawing it
# here is what keeps ordinary published data out of the reading — an RFC 3339
# timestamp file parses as a JSON scalar, and without the flatness rule a
# nested JSON document would come back as a fake instruction with fake
# operands.
export def deref-file [file: path cid: string]: nothing -> any {
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

# Files that could name this CID: everything under links/ and particles/,
# narrowed by a text search when `rg` is on PATH. bj002 names the search
# itself — an operand's CID is a literal string in every record that mentions
# it, so `rg` finds the whole neighbourhood of a vertex without reading the
# graph. It is only a narrowing: a file that does not contain the string cannot
# name the CID, so dropping it changes nothing, and every file that survives is
# read and checked exactly as it would have been. `--scan` forces the full read
# — the same answer, slower — and the tests run both ways against each other,
# because an optional fast path that nothing exercises is a path that rots.
#
# The rg flags are all correctness, not taste: `--no-config` so a user's
# RIPGREP_CONFIG_PATH cannot add an exclusion, `--no-ignore` so a gitignored
# graph home is still searched, `--hidden` for a dotted store file, `--text` so
# a published binary is not skipped as unreadable. Anything rg silently omits
# here is a link a reader would never see.
export def candidates [root: path cid: string --scan]: nothing -> list<path> {
    let dirs = [(links-dir $root) (particles-dir $root)] | where {|d| $d | path exists }
    if ($dirs | is-empty) { return [] }
    if $scan or (which rg | is-empty) {
        return ($dirs | each {|d| ls $d | get name } | flatten)
    }
    let found = ^rg --no-config --no-ignore --hidden --text --fixed-strings --files-with-matches -- $cid ...$dirs | complete
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
# Two ways a link can name it. Directly: the CID stands in the record, as
# `cid_from`, `cid_to` or `signer` — a signer is named by every link it signed,
# which is what makes a signer's own work countable. Indirectly: an instruction
# preimage names it as an operand, and the link names that record; then the
# role is the endpoint's key, a dot, and the field inside — `cid_from.about`.
# The record may itself be an operand of a bigger record (`answer` is that
# shape), so the step repeats, and the role grows one field per level.
export def touches [root: path cid: string --scan]: nothing -> table {
    let seeds = candidates $root $cid --scan=$scan
    let in_links = $seeds | where {|f| ($f | path dirname) == (links-dir $root) }
    let in_store = $seeds | where {|f| ($f | path dirname) == (particles-dir $root) }

    let direct = $in_links | each {|f|
        let rec = read-link $f
        $rec
        | columns
        | where {|key| ($rec | get $key) == $cid }
        | each {|key| {link: ($f | path parse | get stem) role: $key} }
    } | flatten

    let indirect = $in_store | each {|f|
        let record_cid = $f | path basename | split row "." | first
        let rec = deref-file $f $record_cid
        if $rec == null { [] } else {
            $rec
            | columns
            | where {|key| $key != "op" and ($rec | get $key) == $cid }
            | each {|key|
                touches $root $record_cid --scan=$scan
                | each {|row| {link: $row.link role: (role-path $row.role $key)} }
            }
            | flatten
        }
    } | flatten

    $direct ++ $indirect
}

# Where a CID sits, as one dotted string: the endpoint's own key, then the
# fields walked to reach it.
export def role-path [prefix: string path: string]: nothing -> string {
    if $path == "" { $prefix } else { $"($prefix).($path)" }
}
