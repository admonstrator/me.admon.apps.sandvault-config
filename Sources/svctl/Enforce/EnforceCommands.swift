import ArgumentParser

enum EnforceCommands {
    static let all: [any ParsableCommand.Type] = [RulesCommand.self, FirewallCommand.self, PanicCommand.self, HelperCommand.self]
}
