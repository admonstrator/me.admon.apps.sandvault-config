import Testing
@testable import SandvaultCore

@Suite struct AddressRangeTests {
    @Test func parsesAndMasksIPv4() throws {
        let range = try #require(AddressRange("192.168.1.77/24"))
        #expect(range.description == "192.168.1.0/24")
        #expect(range.contains("192.168.1.200"))
        #expect(!range.contains("192.168.2.1"))
        #expect(AddressRange("10.1.2.3")?.prefixLength == 32)
    }

    @Test func parsesIPv6() throws {
        let range = try #require(AddressRange("fe80::/10"))
        #expect(range.family == .ipv6)
        #expect(range.contains("fe80::1"))
        #expect(range.contains("febf:ffff::1"))
        #expect(!range.contains("fec0::1"))
        #expect(AddressRange("::1")?.contains("0:0:0:0:0:0:0:1") == true)
        #expect(AddressRange("::ffff:10.0.0.1")?.family == .ipv6)
    }

    @Test func rejectsGarbage() {
        for text in ["", "1.2.3", "1.2.3.4/33", "256.1.1.1", "1.2.3.4/x", "fe80::1%en0", "1::2::3", "a.b.c.d", "1.2.3.4/24/1"] {
            #expect(AddressRange(text) == nil, "\(text)")
        }
    }

    @Test func familiesDoNotMix() {
        #expect(AddressRange("0.0.0.0/0")?.contains("::1") == false)
    }

    @Test func privateNetworks() {
        for address in ["127.0.0.1", "10.4.5.6", "172.20.0.1", "192.168.178.1", "169.254.1.1", "100.100.1.1", "::1", "fd00::5", "fe80::2", "0.0.0.0"] {
            #expect(PrivateNetworks.isPrivate(address), "\(address)")
        }
        for address in ["1.1.1.1", "140.82.112.3", "2606:4700::1111", "172.32.0.1"] {
            #expect(!PrivateNetworks.isPrivate(address), "\(address)")
        }
    }
}
