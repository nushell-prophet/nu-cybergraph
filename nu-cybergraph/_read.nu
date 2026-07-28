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

use _layout.nu [links-dir]
use _particle.nu [index-find particle-verify]
use _record.nu [read-link]

# Every link record in the graph home, each checked against its own address by
# read-link. Sorted by CID so a reading is reproducible across filesystems.
export def read-links [root: path]: nothing -> table {
    let dir = links-dir $root
    if not ($dir | path exists) { return [] }
    ls $dir | get name | sort | each {|f| {cid: ($f | path parse | get stem)} | merge (read-link $f) }
}

# The record an endpoint publishes, or null when this repo holds no file for
# that CID (legitimate — a cyberlink names CIDs and the bytes need not be
# local) or the file is not an instruction preimage. Takes the store index the
# reader built once (_particle.nu store-index), not a repo root: a reading
# dereferences both ends of every link, and one listing per lookup is what made
# that quadratic.
#
# Not an instruction preimage means: not JSON, not a JSON object, or an object
# with a non-string value. The last is the format's own line (_derive.nu: a
# canonical record is flat, values are strings, a reference to another record
# is its CID), and drawing it here is what keeps ordinary published data out of
# the reading — an RFC 3339 timestamp file parses as a JSON scalar, and without
# the flatness rule a nested JSON document would come back as a fake
# instruction with fake operands.
export def deref [index: record cid: string]: nothing -> any {
    let file = index-find $index $cid --optional
    if $file == null { return null }
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

# Every CID an endpoint names, each with the path where it sits: "" for the
# endpoint itself, `about` for a field of its record, `cid_from.about` for a
# field of a record nested one level down (`answer` is the shape that goes
# there). The `op` value is skipped — it is the format's own word, the one
# position in the grammar that is not an operand.
#
# Recursion terminates on its own: a derived CID is the hash of the record it
# names, so a record cannot contain its own address, and a chain of them has to
# bottom out in operands the store does not resolve.
export def mentions [index: record cid: string]: nothing -> table {
    let here = [{cid: $cid path: ""}]
    let rec = deref $index $cid
    if $rec == null { return $here }
    $here ++ (record-mentions $index $rec)
}

# The same walk over a record already dereferenced. Split out because a reader
# that holds the record — every caller walking the whole graph does — would
# otherwise pay for a second dereference of the endpoint it just read, and that
# doubled the cost of a full reading.
export def record-mentions [index: record rec: record]: nothing -> table {
    $rec
    | columns
    | where $it != "op"
    | each {|key|
        mentions $index ($rec | get $key)
        | each {|m| {cid: $m.cid path: (role-path $key $m.path)} }
    }
    | flatten
}

# Where a CID sits, as one dotted string: the endpoint's own key, then the
# fields walked to reach it. One definition, because `mentions` builds these
# paths and `link touching` extends them by the endpoint they came from.
export def role-path [prefix: string path: string]: nothing -> string {
    if $path == "" { $prefix } else { $"($prefix).($path)" }
}
