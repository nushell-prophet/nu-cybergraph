# The position — a link's number in its signer's run, one small file per link
# at order/<signer-cid>/<edge-cid>.order.json, written by `link add` beside the
# record and frozen by the seal that catalogues both.
#
# What the number is for is not indexing: it is bostrom's account sequence
# (bj002ru line 88). A run with no gaps makes a signer's record provably
# complete, so a replica cannot be silently thinned — the property Secure
# Scuttlebutt's per-feed counter and Certificate Transparency's log have.
#
# Why a file per link and not one CSV: an inclusion proof carries sibling
# HASHES, never sibling contents (RFC 6962), so the merkle tree already gives
# selective disclosure per leaf — and a leaf is a file. A row inside a shared
# log is not a leaf, and proving one row of it means shipping the whole log,
# the exact inverse of why link records are separate files. The directory IS
# the log; a reading that prints a table is a walk over it.
#
# Why the number is not in the record bytes: a counter inside {cid_from,
# cid_to} forks one act into a different CID per recording moment — SPEC 3.1's
# own argument for keeping time out — and worse here, because the pair is the
# SHARED edge address, so a per-signer counter would fork the edge itself.
# Not in the birth certificate either: verification folds `leaf` through `path`
# to the signed root and checks nothing else, so a `seq` there is covered by no
# signature and no root.
#
# And not in the position's own bytes: a certificate names the root, so it
# cannot sit inside the tree that produces it. The position must, so it states
# only its one key; which seal minted it is answered by the proof it verifies
# against, exactly as for a link record.
#
# Who mints the number is the seal and not the writer. `link add` writes a
# time, because numbering has to happen somewhere that sees the whole run at
# once, and the seal is the only such moment — it is also where a merge of two
# checkouts arrives, since two adds under different edges conflict on nothing
# and git merges both silently.

use _layout.nu [ order-files link-files ]
use _validate.nu [ assert-utc-timestamp ]

# The two states, one key each, and never both. A record and not a bare value,
# so the key IS the state: nothing has to infer "not numbered yet" from whether
# a proof lies beside the file.
#
# `added_at` while provisional, `seq` once a seal has numbered it. The
# provisional value is a TIME and not a counter, because two checkouts each
# counting 42, 43, 44 can only be merged by putting one run wholly before the
# other, which is not the order the acts happened in. Times interleave, so the
# seal's sort recovers the real order instead of inventing a plausible one. The
# cost is clock skew between machines instead of colliding counters — the
# better failure of the two, because it degrades the order without duplicating
# anything.
#
# `added_at` is UTC and nothing else (_validate.nu RFC3339_UTC_RE), enforced at
# the write and at the read: an unsigned time is only worth reading if two
# files stating one instant state it one way.
const PROVISIONAL_KEYS = [added_at]
const NUMBERED_KEYS = [seq]

# A decimal count with no leading zeros, starting at 0 — the root statement's
# own rule for its own counter (SPEC 7), reused rather than invented, and a
# STRING for the same reason it is one there: the format's records hold
# strings, so nothing has to agree about integer width or JSON number
# rendering.
const SEQ_RE = '^(0|[1-9][0-9]*)$'

# Enforce the position shape: exactly one of the two key sets, and nothing in
# between. By exact key set, so `{"seq": "0", "added_at": …}` and
# `{"seq": "2026-08-31T…"}` are both refused — a file that states two states at
# once, or one key holding the other's value, is not a position in either
# state.
export def validate-position [rec: record]: nothing -> nothing {
    let cols = $rec | columns | sort

    if $cols == $PROVISIONAL_KEYS {
        assert-utc-timestamp $rec "added_at" "position"
    } else if $cols == $NUMBERED_KEYS {
        if ($rec.seq | describe) != "string" or $rec.seq !~ $SEQ_RE {
            error make {msg: $"position seq must be a decimal string with no leading zeros: ($rec.seq | to json)"}
        }
    } else {
        error make {msg: $"position must hold exactly one key — `added_at` while provisional, `seq` once a seal has numbered it — got ($cols | str join ', ')"}
    }
}

# Write one position. JSON, 2-space indent, no trailing newline — the birth
# certificate's own formatting, and free to choose for the same reason: the
# bytes are not self-addressed, so nothing derives an address from them. What
# proves them is the seal.
export def save-position [file: path rec: record]: nothing -> nothing {
    validate-position $rec
    $rec | to json --indent 2 | save --raw --force $file
}

# The provisional position: the moment the act was recorded, and nothing else.
# A claimed time does enter the graph home, but as scaffolding the seal
# deletes — it is replaced before staging, so no signature ever covers it and
# the graph attests no times.
#
# A datetime and not a string, so UTC is not something a caller can get wrong:
# the conversion happens here, at the one door a position is written through,
# and `validate-position` is the same rule read back off the bytes.
export def write-added-at [file: path when: datetime]: nothing -> nothing {
    save-position $file {added_at: ($when | date to-timezone UTC | format date "%+")}
}

# The numbered position, written by the seal and never moved again.
export def write-seq [file: path seq: int]: nothing -> nothing {
    save-position $file {seq: ($seq | into string)}
}

# What a position file states, validated on the way out — a record with exactly
# one key, so the caller reads the state off the key rather than guessing it.
# A hand-edited `{"seq": 7}` or `{"seq": "007"}` fails at the reader rather
# than being numbered into something plausible.
export def read-position [file: path]: nothing -> record {
    let rec = open --raw $file | from json

    validate-position $rec
    $rec
}

# Every position in the graph home, its state named once: `provisional` says
# which of the two columns the file filled, `seq` for the numbered and
# `added_at` for the provisional.
#
# The state is discriminated HERE and nowhere else. A caller that re-derived it
# from `seq != null` in one place and `added_at != null` in another would be
# saying one thing in two vocabularies, and the two would read differently the
# first time a file arrived holding neither.
#
# A file states exactly one key (validate-position), so laying it over a
# template of nulls fills the column that key names and leaves the other empty.
export def positions [root: path]: nothing -> table {
    order-files $root
    | each {|r|
        let state = {seq: null added_at: null} | merge (read-position $r.file)

        $r | merge {
            # A string on disk, for the reason SEQ_RE gives; a number here,
            # because a run is compared and counted, never rendered.
            seq: (if $state.seq == null { null } else { $state.seq | into int })
            added_at: $state.added_at
            provisional: ($state.seq == null)
        }
    }
}

# Every link has exactly one position and every position names a link.
#
# Without both halves the number does not do the job it exists for: a signer
# could seal a link and simply not number it, and a reader holding the whole
# graph would see a contiguous run beside an unnumbered link — silent thinning,
# precisely what the sequence exposes. Exactly one is the path's own doing:
# signer and edge address one file, so the two sets are compared and that is
# the whole check.
export def assert-bijection [root: path]: nothing -> nothing {
    let links = link-files $root | format pattern '{signer}/{edge}'
    let numbered = order-files $root | format pattern '{signer}/{edge}'
    let unnumbered = $links | where $it not-in $numbered

    if ($unnumbered | is-not-empty) {
        error make {msg: $"link records with no position: ($unnumbered | str join ', ') — every link a seal catalogues carries its number in the signer's run, or a withheld link is indistinguishable from one that was never made. A record written by hand is not numbered by anything" help: "remove it and re-run `nu-cybergraph link add`, or `nu-cybergraph order backfill` on a graph that predates the run"}
    }
    let orphans = $numbered | where $it not-in $links

    if ($orphans | is-not-empty) {
        error make {msg: $"positions naming no link record: ($orphans | str join ', ') — a number in the run without the act it counts" help: "remove the position, or restore the record it belongs to"}
    }
}

# The numbered run of every signer must be 0..N with no gap and no repeat.
#
# Read over the numbered set and not over what a proof covers, because
# `seq` is what "already assigned" means: a seal that died between numbering
# and freezing left numbers no proof covers, and handing those out a second
# time is how one number ends up counting two acts.
#
# Refused rather than repaired, and it is the refusal `seal chain` already
# makes about a missing snapshot, for the same reason: a hole at 3 is not
# fillable, because everything around it is signed and would be cemented by
# this seal instead of reported. A seal is exactly where junk must stop being
# junk quietly.
#
# The empty run passes: a graph before its first seal has nothing numbered, and
# that is the ordinary state, not a gap.
export def assert-numbered-run [root: path]: nothing -> nothing {
    for signer in (positions $root | where not $it.provisional | group-by signer --to-table) {
        let seqs = $signer.items | get seq | sort

        # The rule read directly: a run of 0..N with no gap and no repeat is a
        # run where every number equals its own index once sorted.
        if ($seqs | enumerate | any {|r| $r.item != $r.index }) {
            error make {msg: $"($signer.signer)'s numbered run breaks: ($seqs | str join ', ') — a run of numbered positions must be 0..N with no gap and no repeat, and a hole cannot be numbered away because the numbers around it are signed. Every certificate in this run states a completeness this graph no longer has"}
        }
    }
}

# Every position with the number it holds or the number it is going to get,
# `provisional` saying which — one row per position, per signer run.
#
# The projection is one piece of code because it has one meaning: the number a
# provisional position will receive is whatever the next seal assigns it, so a
# reading that computed it a second way would be a second numbering rule, right
# up until the two disagreed. `number-provisional` writes what this returns and
# `order list` prints it.
#
# A projected number is not a promise. Another add before the seal takes a
# number in this run if it arrived earlier, and everything after it shifts —
# which is why `provisional` is a column and not a footnote.
export def project-run [root: path]: nothing -> table {
    positions $root
    | group-by signer
    | values
    | each {|rows| project-signer-run $rows }
    | flatten
}

# One signer's run: what is already numbered, unchanged, then what is waiting,
# numbered after it.
#
# The assigned rows are passed through untouched, never re-derived. Numbering
# them from their position in the sorted run would give the same answer only
# while the run is unbroken, and over a run with a hole it would hand a number
# that is already signed to a second act — which is the failure
# `assert-numbered-run` exists to stop, so nothing here may depend on it having
# run.
#
# The waiting ones are sorted by `added_at`, ties broken byte-wise by edge CID
# — the manifest's own ordering rule, so nothing new decides it — and numbered
# consecutively after the highest already assigned. Sorted as a TIME and not as
# a string: every claimed time is UTC (validate-position), but `Z`, `+00:00`
# and fractional seconds still put one instant in several byte orders, and only
# the parse compares those correctly.
export def project-signer-run [rows: table]: nothing -> table {
    let assigned = $rows | where not $it.provisional
    let next = if ($assigned | is-empty) { 0 } else { ($assigned | get seq | math max) + 1 }
    let waiting = $rows
        | where $it.provisional
        | insert arrived {|r| $r.added_at | into datetime }
        | sort-by arrived edge
        | reject arrived

    $assigned | append ($waiting | enumerate | each {|r| $r.item | update seq ($next + $r.index) })
}

# Turn every provisional position into a numbered one, and return how many.
#
# This is where a number comes from at all: numbering needs a moment that sees
# the whole run at once, and the seal is the only one. It is also where a merge
# of two checkouts lands — two adds under different edges conflict on nothing,
# so git merges both silently and neither writer ever saw the other's run.
#
# Runs AFTER `assert-numbered-run`, never instead of it: the highest assigned
# number is where the new numbering starts, and over a run with a hole that
# number is one the graph has already signed.
export def number-provisional [root: path]: nothing -> int {
    let minted = project-run $root | where $it.provisional

    # `for`, not `each`: a raise inside an `each` closure comes back as "Eval
    # block failed with pipeline input", and a half-numbered run is what the
    # operator would then have to read the state of.
    for row in $minted {
        write-seq $row.file $row.seq
    }
    $minted | length
}
