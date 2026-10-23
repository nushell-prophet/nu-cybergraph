# Why: the submodules export everything so tests can `use` any helper; this file names the public commands.
# A named list flattens the namespace, so each file's subcommands go through an inline module of the same name,
# and `main` is imported outside it: inside a wrapper module it would surface as `seal seal`, not `seal`.
export use init.nu [ main ]
module particle { export use particle.nu [ add add-edge add-link cat uncommitted ] }
export use particle
export use strays.nu [ main ]
module link { export use link.nu [ add imported list tally touching ] }
export use link
module order { export use order.nu [ backfill list ] }
export use order
module convention {
    export use convention.nu [
        agree-particle answer-edge author-particle claimed-at con confirm-edge confirm-link deny-edge deny-link derive
        disagree-particle pro question quote-particle repeat same translation-particle update-edge update-particle
    ]
}
export use convention
export use seal.nu [ main ]
module seal { export use seal.nu [ chain ] }
export use seal
export use bundle.nu [ main ]
export use import.nu [ main ]
export use verify.nu [ main ]
export use verify-bundle.nu [ main ]
