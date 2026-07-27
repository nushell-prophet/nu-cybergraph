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
        | where {|f| $suffix == "" or ($f | path basename | str ends-with $suffix) }
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
