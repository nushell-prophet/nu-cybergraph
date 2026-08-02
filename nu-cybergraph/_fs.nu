# Directory listing where the directory is data, not a pattern.
#
# Why not `glob ($dir | path join "*.pub")`: the pattern is built by
# interpolation, so any `[`, `*`, `?` or `{` in $dir is read as pattern syntax
# and the call returns an empty list. A graph checked out to `~/proj[v1]` was
# enough — measured: 3 link records on disk, 0 rows out. Every failure of that
# shape is silent, and most of the sites here are verification: seal's
# pre-seal self-addressing sweep iterated over nothing, so a repo at such a
# path sealed WITHOUT validating any record. `ls` takes a variable argument as
# a literal path, so listing and filtering by name keeps the path as data.
#
# Same helper, same reasoning, as nu-multiproof's `_fs.nu` — duplicated (not
# imported) for the reason `_repo.nu` gives: cross-repo imports of another
# project's `_`-internals carry no compatibility promise.

# Files (anything that is not a directory, symlinks included) directly in
# $dir, or under it with --recursive. Absent directory -> []. Names are
# compared literally, never as patterns.
#
# Why --all: a dotfile is still a file the caller must see. The glob form this
# replaces did list them, and a bundle manifest that skips `.hidden` is a file
# the receipt does not commit to.
export def list-files [
    dir: path
    --recursive # walk subdirectories too
    --suffix: string = "" # keep only names ending with this
]: nothing -> list<path> {
    if not ($dir | path exists) { return [] }
    let entries = ls --all $dir
    let here = $entries
        | where type != dir
        | get name
        | where ($suffix == "" or ($it | path basename | str ends-with $suffix))
    if not $recursive {
        return $here
    }
    let deeper = $entries
        | where type == dir
        | get name
        | each {|sub| list-files $sub --recursive --suffix $suffix }
        | flatten
    $here ++ $deeper
}

# Subdirectories directly in $dir. Absent directory -> [].
export def list-dirs [dir: path]: nothing -> list<path> {
    if not ($dir | path exists) { return [] }
    ls --all $dir | where type == dir | get name
}

# Copying, where "it did not copy" is an error rather than a line on stderr.
#
# `cp` does not raise when it cannot read a source file: the message goes to
# stderr and the command exits 0. Measured on 0.114.1, both forms — one file
# with mode 000 gave `try` the answer "no error raised" and the destination
# was simply short by that file.
#
# What that costs here: `import` recomputes the receipt's `files` manifest FROM
# the destination, so a truncated copy produces a receipt committing to the
# truncation. Everything after that is self-consistent — every verification
# passes, and the missing bytes are invisible forever. It is the only failure
# in this module that yields a wrong answer indistinguishable from a right one,
# which is why the check belongs at the copy and not at any one caller.
#
# Not a guard bolted onto the two bundle copies: the hole is in `cp` itself, so
# every copy in this module goes through these two.

# Copy one file. Raises if it could not be read or could not be written. $dst
# may be a directory (the file keeps its name) or the full destination path.
#
# Written with open/save rather than `cp` + a check afterwards, because there is
# then nothing to check: `open --raw` raises `PermissionDenied` naming the path
# when the source cannot be read, and `save` raises when the destination cannot
# be written or its directory does not exist (measured on 0.114.1). A failed
# copy is an error at the point the contract breaks instead of a return value
# somebody has to compare. `into binary` and not a bare pipe: `open --raw`
# hands back a STRING when the bytes happen to be valid UTF-8, and these files
# are signatures and OTS proofs.
#
# No `--force`: `save` refuses an existing destination, and `cp` overwrote one
# silently. Nothing legitimate is affected — every call site here writes a fresh
# path under a directory it has just made — and silent overwriting is a named
# open defect in this repo (the seal freeze loop clobbers a frozen certificate
# exactly that way). A copy that lands on something is a question, not a no-op.
#
# It also dereferences a symlinked source, where `cp` preserved the link. Every
# source reaching this function is a file this repo wrote. A FOREIGN tree is
# copy-tree's job, and that is where following a link would read bytes the
# bundle does not contain — refused there by name.
export def copy-file [src: path dst: path]: nothing -> nothing {
    let landed = if ($dst | path exists) and ($dst | path type) == "dir" {
        $dst | path join ($src | path basename)
    } else { $dst }
    open --raw $src | into binary | save --raw $landed
}

# Copy a directory tree and prove the destination holds the same files with the
# same bytes. $dst must not already exist — it becomes the copy, and it is
# removed again if the copy turns out short, so a refusal leaves no half-built
# tree behind.
#
# The cleanup is this function's own: `import` refuses a destination that
# already exists, so a stranded partial copy would make the retry impossible
# and the operator would have to delete it by hand, inside a tree the repo
# calls read-only. Removing what this call created is not a guard against some
# other failure — it is the undo for the one being reported.
#
# Which is exactly why the precondition is CHECKED and not merely documented:
# with an existing $dst, `cp --recursive` nests the copy inside it, the
# comparison then reports "not faithful", and the cleanup would delete a
# directory this call did not create. A comment cannot hold that line.
export def copy-tree [src: path dst: path]: nothing -> nothing {
    if ($dst | path exists) {
        error make {msg: $"copy-tree destination already exists: ($dst) — it must be the copy, not a directory to copy into"}
    }
    let source = $src | path expand
    cp --recursive $source $dst
    let target = $dst | path expand
    # `catch` and not `finally`: the cleanup must run only on the failing path,
    # or a good copy would be deleted. `error make $e.raw` re-raises the value
    # itself, so nothing is rebuilt from `$e.msg` and nothing is lost — the
    # shape `bundle` already uses for its own cleanup.
    try {
        assert-same-tree $source $target
    } catch {|e|
        rm --recursive --force $target
        error make $e.raw
    }
}

# The comparison half, split out so the cleanup above wraps nothing else.
def assert-same-tree [source: path target: path]: nothing -> nothing {
    # Names before bytes, deliberately: an unreadable source file is listed by
    # `ls` but absent from the destination, so it is named here as lost — no
    # read of it is attempted, and the operator gets "the copy is short"
    # instead of a bare permission error about a file they never named.
    let want = list-files $source --recursive | path relative-to $source | sort
    let got = list-files $target --recursive | path relative-to $target | sort
    let lost = $want | where $it not-in $got
    let extra = $got | where $it not-in $want
    if ($lost | is-not-empty) or ($extra | is-not-empty) {
        error make {msg: $"copy of ($source) into ($target) is not faithful — missing: ($lost | str join ', ') | unexpected: ($extra | str join ', ')"}
    }
    # Refused by name before anything is opened. `list-files` reports a symlink
    # as a file (its own docstring says so), `cp --recursive` preserves it, and
    # `open --raw` then FOLLOWS it — so a dangling link in a foreign bundle came
    # back as the two words `Not found`, and a link to a directory as an opaque
    # IO error. Both are the crash-instead-of-verdict shape this module has just
    # spent a commit removing, and the input here is attacker-controlled.
    #
    # This is not the symlink hardening the audit index asks for: it says what
    # this copy will not carry, nothing more. `bundle-manifest` still hashes
    # through symlinks, and that half stays open.
    for p in $want {
        let s = $source | path join $p
        if ($s | path type) != "file" {
            error make {msg: $"($p) under ($source) is not a regular file \(($s | path type)) — a bundle carries files, and following a link would read bytes it does not contain"}
        }
    }
    # `for`, not `each`: an error raised in an `each` closure is re-wrapped as
    # "Eval block failed with pipeline input" and the real message never
    # reaches the caller.
    for p in $want {
        if (open --raw ($source | path join $p) | hash sha256) != (open --raw ($target | path join $p) | hash sha256) {
            error make {msg: $"copy did not arrive intact: ($p) differs between ($source) and ($target)"}
        }
    }
}
