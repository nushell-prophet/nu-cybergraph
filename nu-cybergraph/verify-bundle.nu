# Verify a portable bundle directory — the command a stranger runs.
#
# README "Bundles, import, provenance" claims anyone can check a received bundle
# offline with no access to the origin repo, and this file is that claim's command:
# a public name over the checker in `_verify-helpers.nu`, and nothing more. No
# other entry point answers it — `verify` takes an edge CID and looks in this
# repo's signer directories, certs/ and imported/; `import` needs an initialized
# repo with a registered pubkey and writes a custody receipt, a commitment
# rather than a check — and a leading `_` means internal to this module, which
# is not something a recipient can be told to import.
#
# Its own file, not a subcommand of `verify`: an `export def bundle` inside
# `verify.nu` shadows that file's own `use bundle.nu`, silently (probed on
# 0.114.1), so a caller asking for one command quietly gets the other.

use _verify-helpers.nu [ verify-bundle ]

# Verify a received bundle against the seal it was born under. Needs no repo,
# no key and no network: everything the check reads is inside the directory.
@category cybergraph
@example "check a bundle someone handed you" { verify-bundle ./received/QmXo… }
export def main [
    bundle: path # Bundle directory: the birth proof as `bundle` exported it
]: nothing -> record {
    # Checked here rather than left to the certificate lookup inside: a mistyped path
    # otherwise surfaces as "expected exactly one *.cert.json at the root of X,
    # found 0", which reads as a verdict about the bundle instead of about the
    # argument.
    if not ($bundle | path exists) {
        error make {
            msg: $"no such bundle directory: ($bundle)"
            label: {text: "no such directory" span: (metadata $bundle).span}
        }
    }
    if ($bundle | path type) != "dir" {
        error make {
            msg: $"($bundle) is not a directory — a bundle is the directory `bundle` wrote, not a file inside it"
            label: {text: "not a directory" span: (metadata $bundle).span}
        }
    }
    verify-bundle $bundle
}
