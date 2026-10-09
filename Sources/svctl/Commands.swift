import ArgumentParser

/// Each agent registers its commands in its own `<Area>Commands.all`; this list only concatenates them.
let allSubcommands: [any ParsableCommand.Type] =
    ObserveCommands.all + EnforceCommands.all + NetCommands.all + WorkflowCommands.all
