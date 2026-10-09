// swift-tools-version:6.0
import PackageDescription

let argumentParser: Target.Dependency = .product(name: "ArgumentParser", package: "swift-argument-parser")

let package = Package(
    name: "SandvaultConfig",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SandvaultCore", targets: ["SandvaultCore"]),
        .library(name: "SandvaultObserve", targets: ["SandvaultObserve"]),
        .library(name: "SandvaultEnforce", targets: ["SandvaultEnforce"]),
        .library(name: "SandvaultNet", targets: ["SandvaultNet"]),
        .library(name: "SandvaultWorkflow", targets: ["SandvaultWorkflow"]),
        .executable(name: "svctl", targets: ["svctl"]),
        .executable(name: "sandvault-netd", targets: ["sandvault-netd"]),
        .executable(name: "svctl-helper", targets: ["svctl-helper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.80.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.30.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.10.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
    ],
    targets: [
        // Contract: shared models, environment, command runner, protocols. Owned by the lead.
        .target(name: "SandvaultCore"),

        // Agent A: status/doctor, processes, sessions, connections, violations.
        .target(name: "SandvaultObserve", dependencies: ["SandvaultCore"]),

        // Agent B: SBPL and pf generation, profile merge, privileged helper logic.
        .target(
            name: "SandvaultEnforce",
            dependencies: ["SandvaultCore", .product(name: "Crypto", package: "swift-crypto")]
        ),

        // Agent C: proxy, DNS forwarder, policy engine, TLS inspection, control socket.
        .target(
            name: "SandvaultNet",
            dependencies: [
                "SandvaultCore",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),

        // Agent D (phase 2): hand-off, repos, tools, migration.
        .target(name: "SandvaultWorkflow", dependencies: ["SandvaultCore"]),

        .executableTarget(
            name: "svctl",
            dependencies: [
                "SandvaultCore", "SandvaultObserve", "SandvaultEnforce", "SandvaultNet", "SandvaultWorkflow",
                argumentParser,
            ]
        ),
        .executableTarget(
            name: "sandvault-netd",
            dependencies: ["SandvaultCore", "SandvaultObserve", "SandvaultEnforce", "SandvaultNet", argumentParser]
        ),
        .executableTarget(
            name: "svctl-helper",
            dependencies: ["SandvaultCore", "SandvaultEnforce", argumentParser]
        ),

        .testTarget(name: "SandvaultCoreTests", dependencies: ["SandvaultCore"], resources: [.copy("Fixtures")]),
        .testTarget(name: "SandvaultObserveTests", dependencies: ["SandvaultObserve"], resources: [.copy("Fixtures")]),
        .testTarget(name: "SandvaultEnforceTests", dependencies: ["SandvaultEnforce"], resources: [.copy("Fixtures")]),
        .testTarget(name: "SandvaultNetTests", dependencies: ["SandvaultNet"], resources: [.copy("Fixtures")]),
        .testTarget(name: "SandvaultWorkflowTests", dependencies: ["SandvaultWorkflow"], resources: [.copy("Fixtures")]),
    ]
)
