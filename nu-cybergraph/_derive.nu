# The derived-CID primitive of bj002 — the one operation every convention
# stands on. Spec-critical byte format, pinned by golden tests in
# tests/test_convention.nu; same discipline as _record.nu. Changing the join
# or the byte encoding breaks every derived CID — treat as a format version
# bump, not an edit.
#
# `hash(x, y, …)` from the journal: join the argument strings with commas and
# take the CID v0 of the resulting bytes. No trailing newline — the spec says
# "the CID of the string of arguments joined with commas", so the preimage is
# exactly that string and nothing more. The two special cases of the appendix
# fall out of the same call: the edge address is `derive $from $to`, the
# cyberlink's derived CID is `derive $from $to $neuron`.

use _deps/cid-v0.nu [cid-v0]

# The preimage hash() operates on: the arguments joined with commas. Published
# as a particle so a reader can dereference a derived CID back to its parts
# (bj002 "Reading instructions"). One definition of the join, shared by
# `derive` and by the convention layer that publishes it.
export def preimage [...args: string]: nothing -> string {
    $args | str join ","
}

# hash(...args): the CID v0 of the preimage bytes — a derived CID.
export def derive [...args: string]: nothing -> string {
    preimage ...$args | into binary | cid-v0
}
