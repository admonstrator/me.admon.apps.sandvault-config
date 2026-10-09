import ArgumentParser
import Foundation
import SandvaultCore

/// Options every command accepts: `@OptionGroup var global: GlobalOptions`.
struct GlobalOptions: ParsableArguments {
    @Flag(name: .long, help: "Print machine-readable JSON instead of text.")
    var json = false

    @Option(name: .long, help: "Path to config.json (default: ~/Library/Application Support/<bundle id>/config.json).")
    var config: String?

    var environment: SandvaultEnvironment { .current() }
    var paths: AppPaths { AppPaths(environment: environment) }
    var configStore: ConfigStore { ConfigStore(path: config ?? paths.configFile) }
    var runner: CommandRunner { ProcessCommandRunner() }
}
