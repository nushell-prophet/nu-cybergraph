# Import a foreign link's bundle into this repo, verifying before anything
# lands. The bundle stays intact under imported/<neuron-cid>/<link-cid>/ — it
# remains the link's authority for authorship and birth time through any
# number of re-exports (re-export = pass the directory along unchanged).

use _repo.nu repo-root
use _verify-helpers.nu [verify-bundle]

export def main [
    bundle: path # Portable bundle directory to import
    --repo: path # Destination repo root (default: git root of current directory)
]: nothing -> record {
    let root = repo-root $repo
    let v = verify-bundle $bundle
    if not $v.valid {
        error make {msg: $"refusing to import: ($v.error)"}
    }
    let link_cid = $v.leaf.filepath | path parse | get stem
    let dest = $root | path join imported $v.neuron.cid $link_cid
    if ($dest | path exists) {
        error make {msg: $"already imported: ($dest)"}
    }
    mkdir ($dest | path dirname)
    cp -r ($bundle | path expand) $dest
    print $"Imported: ($dest)"
    {link: $link_cid neuron: $v.neuron.cid path: $dest ots: $v.ots.status}
}
