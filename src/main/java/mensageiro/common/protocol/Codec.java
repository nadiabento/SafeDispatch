package mensageiro.common.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public final class Codec {
    private Codec() {}

    public static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        public Writer u8(int v) { out.write(v); return this; }
        public Writer u32(long v) {
            out.write((int) (v >>> 24)); out.write((int) (v >>> 16)); out.write((int) (v >>> 8)); out.write((int) v);
            return this;
        }
        public Writer u64(long v) { u32(v >>> 32); u32(v & 0xFFFFFFFFL); return this; }
        public Writer bytes(byte[] b) { u32(b.length); out.writeBytes(b); return this; }
        public Writer string(String s) { return bytes(s.getBytes(StandardCharsets.UTF_8)); }
        public byte[] toByteArray() { return out.toByteArray(); }
    }

    public static final class Reader {
        private final byte[] buf;
        private int pos;
        public Reader(byte[] buf) { this.buf = buf; }

        private void need(int n) throws ProtocolException {
            if (n < 0 || n > buf.length - pos) throw new ProtocolException("payload truncado");
        }
        public int u8() throws ProtocolException { need(1); return buf[pos++] & 0xFF; }
        public long u32() throws ProtocolException {
            need(4);
            long v = ((buf[pos] & 0xFFL) << 24) | ((buf[pos + 1] & 0xFFL) << 16) | ((buf[pos + 2] & 0xFFL) << 8) | (buf[pos + 3] & 0xFFL);
            pos += 4; return v;
        }
        public long u64() throws ProtocolException { return (u32() << 32) | u32(); }
        public byte[] bytes(int maxLen) throws ProtocolException {
            long n = u32();
            if (n > maxLen) throw new ProtocolException("campo demasiado grande: " + n);
            need((int) n);
            byte[] b = java.util.Arrays.copyOfRange(buf, pos, pos + (int) n);
            pos += (int) n; return b;
        }
        public String string(int maxLen) throws ProtocolException {
            return new String(bytes(maxLen), StandardCharsets.UTF_8);
        }
        public void end() throws ProtocolException {
            if (pos != buf.length) throw new ProtocolException("bytes a mais no payload");
        }
    }
}
