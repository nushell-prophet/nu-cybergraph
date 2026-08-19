# Verify a portable bundle directory — the command a stranger runs.
#
# README "Portability" claims anyone can check a received bundle offline with
# no access to the origin repo. Everything needed was already here, but the
# only entry points were `verify` (which takes an edge CID and looks in this
# repo's signer directories, certs/ and imported/) and `import` (which needs an initialized repo
# with a registered pubkey, and writes a custody receipt — not a check but a
# commitment). The checking function itself sat in `_verify-helpers.nu`, and a
# leading `_` means internal to this module: the tests reached it by importing
# that file directly, which is not something a recipient can be told to do.
#
# So the claim had no command behind it. This file is that command, and nothing
# more — a public name over the function that already does the work.
#
# Not a subcommand of `verify`. The original reason was a shadowing hazard —
# `export def bundle` inside `verify.nu` shadowed its own `use bundle.nu`, and
# `verify` called `bundle` to materialize an own link before checking it.
# Probed on 0.114.1: the shadowing was silent, and `verify <cid>` quietly ran
# the wrong command. `verify` no longer imports `bundle.nu` at all, so that
# particular trap is gone; the file stays for the reason above it — a received
# bundle needs a public name, and this is it.

use _verify-helpers.nu [ verify-bundle ]

# Verify a received bundle against the seal it was born under. Needs no repo,
# no key and no network: everything the check reads is inside the directory.
@example "check a bundle someone handed you" { verify-bundle ./received/QmXo… }
export def main [
    bundle: path # Bundle directory: the birth proof as `bundle` exported it
]: nothing -> record {
    # Checked here rather than left to the certificate lookup inside: a mistyped path
    # otherwise surfaces as "expected exactly one *.cert.json at the root of X,
    # found 0", which reads as a verdict about the bundle instead of about the
    # argument.
    if not ($bundle | path exists) {
        error make {msg: $"no such bundle directory: ($bundle)"}
    }
    if ($bundle | path type) != "dir" {
        error make {msg: $"($bundle) is not a directory — a bundle is the directory `bundle` wrote, not a file inside it"}
    }
    verify-bundle $bundle
}
