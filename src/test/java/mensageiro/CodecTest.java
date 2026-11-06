package mensageiro;

import mensageiro.common.protocol.*;

public final class CodecTest {
    private static void check(boolean c, String m) { if (!c) throw new AssertionError(m); }

    static void testRoundTrip() throws Exception {
        byte[] data = new Codec.Writer().u8(7).u32(0xFFFFFFFFL).u64(1L << 40).string("ana").bytes(new byte[]{9, 8}).toByteArray();
        var r = new Codec.Reader(data);
        check(r.u8() == 7, "u8"); check(r.u32() == 0xFFFFFFFFL, "u32"); check(r.u64() == (1L << 40), "u64");
        check(r.string(64).equals("ana"), "string"); check(r.bytes(8).length == 2, "bytes"); r.end();
    }

    static void testTruncadoRecusado() throws Exception {
        byte[] data = new Codec.Writer().string("abcdef").toByteArray();
        byte[] cut = java.util.Arrays.copyOf(data, data.length - 2);
        try { new Codec.Reader(cut).string(64); throw new AssertionError("devia falhar"); } catch (ProtocolException ok) { }
    }

    static void testCampoForjadoGigante() throws Exception {
        byte[] data = new Codec.Writer().u32(0x7FFFFFFFL).toByteArray();
        try { new Codec.Reader(data).bytes(1 << 20); throw new AssertionError("devia falhar"); } catch (ProtocolException ok) { }
    }

    static void testBytesAMais() throws Exception {
        var r = new Codec.Reader(new byte[]{1, 2});
        r.u8();
        try { r.end(); throw new AssertionError("devia falhar"); } catch (ProtocolException ok) { }
    }
}
