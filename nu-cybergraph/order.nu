# The run: reading a signer's positions, and the one-time stamping of a graph
# that predates them.
#
# `list` is the reading the design asks for in place of a stored CSV. There is
# none to store: an inclusion proof carries sibling hashes and never sibling
# contents, so a fact you want to prove on its own has to be its own leaf, and
# a leaf is a file (_order.nu). `order/` IS the log; printing it is a walk.
#
# --- the backfill ---
#
# Links written before positions existed have birth certificates and no
# position, so the first seal after the format bump would refuse on the
# bijection `seal` now enforces. This gives each of them the time git recorded
# for it — the commit that ADDED the file — which is unsigned and the only
# record of arrival order that a pre-run graph has, and that is what makes it
# the right one to take. What a backfilled time claims is "this is when the
# repo recorded it", never "this is when I asserted it".
#
# It stamps and does not number. A provisional position states a time, and the
# seal is what turns a time into a number (_order.nu) — so the backfill owns no
# numbering rule of its own, and the next seal numbers these exactly like a
# position `link add` wrote a minute ago.
#
# A command run once, never a migration path the format carries. The stakes
# are part of that decision: there are few cybergraphs and none in production,
# so a graph with nothing to migrate is cheaper than a format that always
# knows how. It refuses the moment any position exists, because a half-stamped
# graph is a question about which half, and only its owner can answer it.
#
# One line of the design holds only for links born after the bump: a
# backfilled position freezes under a LATER root than its link's birth
# certificate, so those bundles carry two seal snapshots instead of one.

use _repo.nu graph-root
use _layout.nu [ link-files order-dir order-path order-files ]
use _order.nu [ write-added-at read-position project-run assert-numbered-run ]
use _validate.nu [ RFC3339_RE ]

# This signer's run as it stands, oldest first: one row per position, with the
# number it holds and the number a provisional one is going to get.
#
# `seq` is the number in either state, and `provisional` is what tells them
# apart — false once a seal has minted the number and frozen a proof beside it,
# true while the position is still the time `link add` wrote. A projected
# number is computed by the sort the seal itself will use (_order.nu
# `project-run`), so it is the run that WOULD be minted now; another act
# arriving before the seal takes a number in the middle if it arrived earlier,
# and everything after it shifts. That is why the column says so rather than
# printing a settled-looking number.
#
# `added_at` is the claimed time a provisional position states, and null once
# the seal has replaced it: the graph attests no times, so the column empties
# exactly when the number becomes provable.
#
# Own links only, the boundary `link list` keeps: `order/` holds what THIS
# signer asserted. An imported bundle is another signer's run, ordered by their
# own seal chain, and mixing the two would turn a reading of one run into a
# reading of everyone's.
#
# Refuses over a numbered run with a hole, the refusal `seal` makes: the
# projection numbers from the highest already assigned, so over a broken run it
# would print numbers no seal will ever mint.
@category cybergraph
@example "the run, numbered and provisional" { nu-cybergraph order list }
@example "what is not numbered yet" { nu-cybergraph order list | where $it.provisional }
export def list [
    --repo: path # Repo root (default: the nearest dir holding cybergraph/, up to the git root)
]: nothing -> table {
    let root = graph-root $repo

    assert-numbered-run $root
    project-run $root
    | select signer edge seq provisional added_at
    | sort-by signer seq
}

# When git first saw each link file: one row per path it ever ADDED under the
# graph home, with the committer date of the commit that did it, in whatever
# offset that committer kept — the position is written in UTC (`_order.nu
# write-added-at` converts), so this reader stays as permissive as git's own
# output.
#
# The committer date and not the author's: what this reads is the order the
# repo recorded, and that is the order commits were made in.
#
# `git log --format=%cI --name-only` prints the date, a blank line, then the
# names — so a line is a date or a path, and the timestamp shape tells them
# apart with nothing to configure (no path under the graph home can match it;
# every one of them carries a `/`). `uniq-by` keeps the first, so a file added,
# deleted and added again arrives when it first arrived.
#
# Why --relative: git names a file from the git root, and the links are named
# from the repo, which can sit below it — one project of a monorepo.
export def arrival-times [repo_root: path graph: path]: nothing -> table {
    let result = ^git -C $repo_root log --reverse --diff-filter=A --relative --format=%cI --name-only -- ($graph | path relative-to $repo_root)
        | complete

    if $result.exit_code != 0 {
        error make {msg: $"git log failed over ($graph): ($result.stderr | str trim) — backfill reads arrival order out of history, so it needs the graph to be in a git repo"}
    }
    $result.stdout
    | lines --skip-empty
    | reduce --fold {at: null rows: []} {|line acc|
        if $line =~ $RFC3339_RE {
            {at: $line rows: $acc.rows}
        } else {
            {at: $acc.at rows: ($acc.rows | append {rel: $line at: $acc.at})}
        }
    }
    | get rows
    | uniq-by rel
}

# Stamp every link in this graph with the time git recorded for it, one
# position file each, and report what was written.
#
# A link git has never seen is refused, by name, and nothing is written. What
# this command takes is the time the REPO recorded, and history says nothing at
# all about a file that was never committed — so there is no arrival time to
# take, and the clock would invent one. That is the rule `seal` already applies
# to an untracked store file: committing is the operator's act, not something
# done on their behalf. Commit them and run the backfill again.
#
# Refused before the first file is written, for the reason the "already holds"
# refusal above gives: a half-stamped graph is a question about which half.
@example "stamp a graph written before positions existed" { nu-cybergraph order backfill }
export def backfill [
    --repo: path # Repo root (default: the nearest dir holding cybergraph/, up to the git root)
]: nothing -> table {
    let root = graph-root $repo
    let repo_root = $root | path dirname
    let held = order-files $root

    if ($held | is-not-empty) {
        error make {msg: $"order/ already holds ($held | length) positions — backfill stamps a graph that predates the run, once. A graph where some links have a position and some do not is a question about which half, and `link add` is what writes one for a new act"}
    }

    let arrival = arrival-times $repo_root $root
    let stamps = link-files $root
        | insert rel {|l| $l.file | path relative-to $repo_root }
        | insert added_at {|l| $arrival | where rel == $l.rel | get --optional 0.at }

    let unseen = $stamps | where added_at == null

    if ($unseen | is-not-empty) {
        error make {msg: $"link records git has never seen: ($unseen | get rel | str join ', ') — a backfill takes the time the repo recorded, and history holds no arrival time for a file that was never committed" help: "commit them, then run the backfill again"}
    }

    # `for`, not `each`: a raise inside an `each` closure comes back as "Eval
    # block failed with pipeline input", and a half-stamped graph is what the
    # operator would then have to read the state of.
    for l in $stamps {
        # The run is per signer directory, so the light `--signer alice`
        # workflow has its own sequence and cannot collide with the identity's.
        mkdir (order-dir $root | path join $l.signer)
        write-added-at (order-path $root $l.signer $l.edge) ($l.added_at | into datetime)
    }
    # Read back rather than reported from the row above: what the position
    # states is UTC, and git's own value carries the committer's offset.
    $stamps | select signer edge | insert added_at {|r|
        read-position (order-path $root $r.signer $r.edge) | get added_at
    }
}
