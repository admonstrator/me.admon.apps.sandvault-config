import Testing
@testable import SandvaultCore

@Suite struct ManagedBlockTests {
    let block = ManagedBlock.sandboxProfile

    @Test func appendsToEmptyAndExistingText() {
        let empty = block.replace(in: "", with: "(allow file-read* (subpath \"/opt\"))")
        #expect(empty == "\(block.begin)\n(allow file-read* (subpath \"/opt\"))\n\(block.end)\n")

        let profile = "(version 1)\n(allow default)\n"
        let updated = block.replace(in: profile, with: "X")
        #expect(updated == "(version 1)\n(allow default)\n\n\(block.begin)\nX\n\(block.end)\n")
        #expect(block.extract(from: updated) == "X")
    }

    @Test func replaceIsIdempotentAndKeepsOutsideText() {
        let profile = "(version 1)\n(allow default)\n"
        let once = block.replace(in: profile, with: "A\nB")
        let twice = block.replace(in: once, with: "A\nB")
        #expect(once == twice)
        let changed = block.replace(in: once, with: "C")
        #expect(block.extract(from: changed) == "C")
        #expect(block.remove(from: changed) == profile)
    }

    @Test func collapsesDuplicateBlocks() {
        let doubled = "x\n\n\(block.begin)\nA\n\(block.end)\ny\n\n\(block.begin)\nB\n\(block.end)\n"
        let fixed = block.replace(in: doubled, with: "C")
        #expect(fixed.components(separatedBy: block.begin).count == 2)
        #expect(block.extract(from: fixed) == "C")
        #expect(fixed.hasPrefix("x\ny\n"))
    }

    @Test func missingOrMalformedBlockIsAbsent() {
        #expect(block.extract(from: "(version 1)") == nil)
        #expect(block.extract(from: "\(block.begin)\nno end marker") == nil)
        #expect(!block.contains(in: "(version 1)"))
    }

    @Test func zshenvBlockUsesHashComments() {
        #expect(ManagedBlock.zshenv.begin.hasPrefix("# >>> sandvault-config: network"))
        #expect(ManagedBlock.sandboxProfile.begin.hasPrefix(";; >>> sandvault-config: rules"))
    }
}
