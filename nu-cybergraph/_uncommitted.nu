# What git holds of the particle store, and whether the graph reaches it.
#
# Why a module of its own rather than a function in `_particle.nu`: the reading
# needs both the store and the graph walk, and `_read.nu` already imports
# `_particle.nu` — putting it in either closes an import cycle.
#
# The question it exists to answer: the seal manifest is every git-tracked file
# under the graph home, so a store file outside the index is bytes no root
# covers, while the link naming it is signed and frozen.

use _layout.nu [ particles-dir store-cid ]
use _read.nu [ reachable-cids ]

# The store files git does not hold clean, one row each — `file` absolute,
# `cid`, `size`, `state`, `tracked`. An empty table is the answer that every
# byte the graph names is already in the index.
#
# Only the dirty files, in git's own sense of the word: a clean store file is in
# the index, so the manifest already covers it and there is nothing left to
# decide about it. It also keeps the cost of a seal proportional to what
# changed, since the seal guard comes through here on every run.
#
# `tracked` is read off the status code, not from a second `git ls-files` call:
# `??` is the one porcelain code meaning "not in the index", which is exactly
# the question the seal guard asks. A staged-not-committed file is tracked, and
# that is not a technicality — `git ls-files` reads the index, so the manifest
# covers it already.
#
# A name under `particles/` that is no address at all is reported with a null
# `cid`, and refused by `seal`: the store's filename rule is what makes every
# reader agree on what it holds, and a seal would catalogue such a file unchecked.
#
# The bytes are NOT hashed back to the name here. Every read path already does
# that where it matters (`particle cat`, the graph reader), and this reading
# answers one question — is the file in the index, and does the graph name it.
# A tamper check bolted on would be a second refusal here, beside the one
# `seal` makes on what this returns.
export def uncommitted-files [root: path]: nothing -> table {
    let dir = particles-dir $root

    if not ($dir | path exists) { return [] }
    let top = ^git -C $root rev-parse --show-toplevel | str trim
    let dirty = ^git -C $root status --porcelain=v1 --untracked-files=all -- $dir
        | lines --skip-empty

    # Before `reachable-cids`, which reads the store and dereferences every
    # endpoint: a clean store is the common case and it costs one `git status`.
    if ($dirty | is-empty) { return [] }
    let reachable = reachable-cids $root

    $dirty | each {|line|
        # `XY <path>`, and `XY <old> -> <new>` for a rename — the new name is
        # the file on disk, so it is the one to classify. A path git had to
        # quote arrives with its quotes still on and fails `store-cid` below,
        # which is the right answer: a name needing quotes is not an address.
        let rel = $line | str substring 3.. | split row " -> " | last
        let file = $top | path join $rel
        # A name under particles/ that is no address reads as null here and
        # stays null in the row. The refusal is `strays`, one rule over the
        # whole graph home — and `seal` enforces it before staging anything.
        # A reading reports what is there; refusing is the seal's job.
        let cid = store-cid $file
        # A tracked file deleted from the working tree: nothing to size, and
        # nothing to stage either. Reported rather than dropped — the graph
        # names bytes that are no longer here, and that is worth seeing.
        let present = ($file | path type) == "file"
        let state = if not $present {
            "missing"
        } else if ($cid in $reachable) {
            "reachable"
        } else {
            "orphan"
        }

        {
            file: $file
            cid: $cid
            size: (if $present { ls $file | get 0.size } else { null })
            state: $state
            tracked: ($line not-starts-with "??")
        }
    }
}

# The rows a proposal should stage: untracked, and reached by the graph. One
# definition, so the command that proposes the commit and the seal guard that
# refuses without one cannot disagree about which files are at stake.
#
# An orphan is never staged, and there is no flag to include it: a file no link
# names is not in the graph, so committing it is a plain `git add` and not this
# command's business. The row still appears in the reading — that a file was
# published and linked to nothing is worth seeing.
export def stageable [rows: table]: nothing -> table {
    $rows | where not $it.tracked and state == "reachable"
}
