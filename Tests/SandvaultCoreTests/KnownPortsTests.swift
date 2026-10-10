import Foundation
import Testing
@testable import SandvaultCore

@Suite struct KnownPortsTests {
    @Test func developerPortsAreListed() {
        let expected: [UInt16: String] = [
            22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 853: "DNS over TLS", 3000: "Dev server", 5173: "Vite",
            8080: "HTTP (alt)", 5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis", 27017: "MongoDB", 9418: "Git", 11434: "Ollama",
        ]
        for (port, name) in expected {
            #expect(KnownPorts.service(port) == KnownService(port: port, name: name))
        }
    }

    @Test func unlistedPortsHaveNoName() {
        #expect(KnownPorts.service(8947) == KnownService(port: 8947, name: nil))
        #expect(KnownPorts.name(0) == nil)
    }

    @Test func theListIsCuratedNotExhaustive() {
        #expect((80...150).contains(KnownPorts.names.count))
        #expect(KnownPorts.names.values.allSatisfy { !$0.isEmpty && $0.count <= 24 })
    }
}
