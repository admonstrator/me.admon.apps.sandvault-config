import NIOCore

/// Splits a byte stream at `\n` (JSON Lines). Lines longer than `maxLength` close the connection.
struct LineFrameDecoder: ByteToMessageDecoder {
    typealias InboundOut = String

    var maxLength = 4 << 20

    struct LineTooLong: Error {}

    mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let newline = buffer.readableBytesView.firstIndex(of: 0x0A) else {
            if buffer.readableBytes > maxLength { throw LineTooLong() }
            return .needMoreData
        }
        let length = newline - buffer.readerIndex
        let line = buffer.readString(length: length) ?? ""
        buffer.moveReaderIndex(forwardBy: 1)
        context.fireChannelRead(wrapInboundOut(line))
        return .continue
    }

    mutating func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        while try decode(context: context, buffer: &buffer) == .continue {}
        if buffer.readableBytes > 0, let rest = buffer.readString(length: buffer.readableBytes), !rest.isEmpty {
            context.fireChannelRead(wrapInboundOut(rest))
        }
        return .needMoreData
    }
}
