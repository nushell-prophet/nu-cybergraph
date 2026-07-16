# Assemble the portable bundle for one link: everything a stranger needs to
# verify it offline, in the layout nu-multiproof's README pins under
# "Verifying without the origin repo".

use _repo.nu graph-root

export def main [
    link_cid: string # CID of a link this repo authored (must have a certificate)
    --repo: path # Source repo root (default: git root of current directory)
    --out: path # Bundle destination (default: exports/<link_cid>)
]: nothing -> path {
    let root = graph-root $repo
    let cert = $root | path join certs $"($link_cid).cert.json"
    if not ($cert | path exists) {
        error make {msg: $"no birth certificate for ($link_cid) — run `nu-cybergraph seal` first"}
    }
    let proof = open --raw $cert | from json
    let root_hex = $proof.root
    let snap = $root | path join seals ($root_hex | str substring 0..11)
    if not ($snap | path exists) {
        error make {msg: $"seal snapshot missing for root ($root_hex) — the certificate predates the seals/ convention?"}
    }

    let out = if $out != null { $out | path expand } else { $root | path join exports $link_cid }
    if ($out | path exists) {
        error make {msg: $"bundle destination already exists: ($out)"}
    }
    mkdir ($out | path join links) ($out | path join multiproofs pubkeys)

    cp ($root | path join $proof.leaf.filepath) ($out | path join links)
    cp $cert ($out | path join $"($link_cid).cert.json")
    glob ($snap | path join *) | each {|f| cp $f ($out | path join multiproofs) }

    # Signer pubkeys, derived from the snapshot's sig names (tree-root.txt.<name>.sig).
    let signers = glob ($snap | path join tree-root.txt.*.sig)
        | each {|s| $s | path basename | str replace "tree-root.txt." "" | str replace ".sig" "" }
        | where $it != ""
    let copied = $signers | each {|name|
        let pub = $root | path join multiproofs pubkeys $"($name).pub"
        if ($pub | path exists) { cp $pub ($out | path join multiproofs pubkeys); $name } else { null }
    } | where $it != null
    if ($copied | is-empty) {
        error make {msg: "no signer pubkey found for the snapshot's signatures — the bundle could never verify"}
    }

    # OTS bundles committing to this root, matched by their frozen root
    # statement. Plain content match — discovery only; verify re-checks the
    # commitment cryptographically.
    let ots_bundles = glob ($root | path join multiproofs ots-timestamps tree-root.*)
        | where {|d|
            let frozen = $d | path join tree-root.txt
            ($frozen | path exists) and (open --raw $frozen | str contains $root_hex)
        }
    if ($ots_bundles | is-empty) {
        print "note: no OTS bundle for this root (sealed with --no-stamp?) — the bundle's timestamp will report absent"
    } else {
        mkdir ($out | path join multiproofs ots-timestamps)
        $ots_bundles | each {|d|
            cp -r $d ($out | path join multiproofs ots-timestamps ($d | path basename))
        }
    }

    print $"Bundle: ($out)"
    $out
}
