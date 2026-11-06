package mensageiro;

import mensageiro.common.protocol.*;
import java.io.*;
import java.util.Arrays;

public final class FrameTest {
    private static void check(boolean c, String m) { if (!c) throw new AssertionError(m); }

    static void testRoundTrip() throws Exception {
        var out = new ByteArrayOutputStream();
        byte[] p = {1, 2, 3, 4, 5};
        Frame.write(out, MessageType.SEND, p);
        Frame.write(out, MessageType.ERROR, new byte[0]);
        var in = new ByteArrayInputStream(out.toByteArray());
        var m1 = Frame.read(in);
        check(m1.type() == MessageType.SEND && Arrays.equals(m1.payload(), p), "frame 1");
        var m2 = Frame.read(in);
        check(m2.type() == MessageType.ERROR && m2.payload().length == 0, "frame 2");
        check(Frame.read(in) == null, "EOF limpo devolve null");
    }

    static void testComprimentoExcessivoRecusadoSemAlocar() throws Exception {
        byte[] evil = {0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 9};
        try { Frame.read(new ByteArrayInputStream(evil)); throw new AssertionError("devia falhar"); }
        catch (ProtocolException expected) { }
    }

    static void testComprimentoZeroRecusado() throws Exception {
        try { Frame.read(new ByteArrayInputStream(new byte[]{0, 0, 0, 0})); throw new AssertionError("devia falhar"); }
        catch (ProtocolException expected) { }
    }

    static void testTipoDesconhecido() throws Exception {
        try { Frame.read(new ByteArrayInputStream(new byte[]{0, 0, 0, 1, 99})); throw new AssertionError("devia falhar"); }
        catch (ProtocolException expected) { }
    }

    static void testFrameTruncado() throws Exception {
        try { Frame.read(new ByteArrayInputStream(new byte[]{0, 0, 0, 10, 9, 1})); throw new AssertionError("devia falhar"); }
        catch (EOFException expected) { }
    }

    static void testEscritaDemasiadoGrande() throws Exception {
        try { Frame.write(new ByteArrayOutputStream(), MessageType.SEND, new byte[Frame.MAX_FRAME]); throw new AssertionError("devia falhar"); }
        catch (ProtocolException expected) { }
    }
}
