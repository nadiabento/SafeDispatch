package mensageiro.common.protocol;

import java.io.*;

public final class Frame {
    private Frame() {}

    public static final int MAX_FRAME = 1 << 20;

    public record Message(MessageType type, byte[] payload) {}

    public static void write(OutputStream out, MessageType type, byte[] payload) throws IOException {
        int len = 1 + payload.length;
        if (len > MAX_FRAME) throw new ProtocolException("frame demasiado grande: " + len);
        byte[] buf = new byte[4 + len];
        buf[0] = (byte) (len >>> 24); buf[1] = (byte) (len >>> 16);
        buf[2] = (byte) (len >>> 8);  buf[3] = (byte) len;
        buf[4] = (byte) type.code;
        System.arraycopy(payload, 0, buf, 5, payload.length);
        out.write(buf);
        out.flush();
    }

    public static Message read(InputStream in) throws IOException {
        int b0 = in.read();
        if (b0 < 0) return null;
        int b1 = in.read(), b2 = in.read(), b3 = in.read();
        if ((b1 | b2 | b3) < 0) throw new EOFException("cabeçalho truncado");
        int len = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        if (len < 1 || len > MAX_FRAME) throw new ProtocolException("comprimento inválido: " + len);
        byte[] body = in.readNBytes(len);
        if (body.length != len) throw new EOFException("frame truncado");
        byte[] payload = new byte[len - 1];
        System.arraycopy(body, 1, payload, 0, payload.length);
        return new Message(MessageType.fromCode(body[0] & 0xFF), payload);
    }
}
