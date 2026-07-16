# Create link records in a neuron repo.

use _repo.nu graph-root
use _record.nu [link-bytes link-cid]
use _deps.nu [cid-v0]

# Derive the repo's own neuron identity: the CID of its registered pubkey.
# With several pubkeys registered the choice is the author's — require --neuron.
def own-neuron-cid [root: path]: nothing -> string {
    let pubs = glob ($root | path join multiproofs pubkeys *.pub)
    match ($pubs | length) {
        0 => (error make {msg: "no pubkey registered — run `nu-cybergraph init` first"})
        1 => (open --raw ($pubs | first) | into binary | cid-v0)
        _ => (error make {msg: "multiple pubkeys registered — pass --neuron explicitly"})
    }
}

# Write a new link record to links/<cid>.json, named by its own content address.
# A particle is any content-addressed file; its CID is the CID v0 of its bytes
# (compute one with nu-multiproof: `open --raw file.md | nu-multiproof cid-v0`).
@example "link two particles by the CIDs of their bytes" { link add QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp }
export def add [
    cid_from: string # CID v0 of the source particle
    cid_to: string # CID v0 of the target particle
    --neuron: string # Author's neuron CID (default: CID of the single registered pubkey)
    --claimed-at: string # RFC 3339 timestamp claimed by the author (default: now, UTC)
    --repo: path # Target repo root (default: git root of current directory)
]: nothing -> record {
    let root = graph-root $repo
    let rec = {
        cid_from: $cid_from
        cid_to: $cid_to
        neuron: (if $neuron != null { $neuron } else { own-neuron-cid $root })
        claimed_at: (if $claimed_at != null { $claimed_at } else {
            date now | date to-timezone UTC | format date "%+"
        })
    }
    let cid = link-cid $rec
    mkdir ($root | path join links)
    let out = $root | path join links $"($cid).json"
    if ($out | path exists) {
        # Same CID = byte-identical record (same edge, author, and claimed_at)
        error make {msg: $"link already exists: ($out)"}
    }
    link-bytes $rec | save --raw $out
    {cid: $cid path: $out record: $rec}
}
