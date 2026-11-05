package mensageiro.common.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Utilitários para trabalhar com byte[].
 *
 * Todos os formatos binários do projeto (envelope, cofre, blocos) são construídos
 * com estes métodos, para que "os bytes exatos" que se assinam sejam sempre
 * os mesmos em quem envia e em quem recebe.
 *
 * Convenção: inteiros em big-endian (network byte order).
 */
public final class Bytes {

    private Bytes() {}

    /** Limite defensivo para campos com prefixo de comprimento (evita alocações absurdas). */
    public static final int MAX_FIELD = 16 * 1024 * 1024; // 16 MiB

    // ---------- inteiros <-> bytes ----------

    public static byte[] fromInt(int v) {
        return ByteBuffer.allocate(4).putInt(v).array();
    }

    public static byte[] fromLong(long v) {
        return ByteBuffer.allocate(8).putLong(v).array();
    }

    public static int toInt(byte[] b, int offset) {
        return ByteBuffer.wrap(b, offset, 4).getInt();
    }

    public static long toLong(byte[] b, int offset) {
        return ByteBuffer.wrap(b, offset, 8).getLong();
    }

    // ---------- strings ----------

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    // ---------- concatenação simples ----------

    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    // ---------- comparação em tempo constante ----------

    /** Compara dois arrays sem sair cedo no primeiro byte diferente. */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    // ---------- hex (útil em testes e logs) ----------

    public static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        if (hex.length() % 2 != 0) throw new IllegalArgumentException("hex com tamanho ímpar");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    // ---------- campos com prefixo de comprimento ----------

    /**
     * Constrói bytes sequencialmente: cada campo é escrito como [4 bytes comprimento][dados].
     * Prefixar o comprimento evita ambiguidades: ("ab","c") e ("a","bc") dão bytes diferentes.
     */
    public static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        public Writer field(byte[] data) {
            out.writeBytes(fromInt(data.length));
            out.writeBytes(data);
            return this;
        }

        public Writer string(String s) { return field(utf8(s)); }

        public Writer integer(int v) { out.writeBytes(fromInt(v)); return this; }

        public Writer lng(long v) { out.writeBytes(fromLong(v)); return this; }

        /** Escreve um byte solto (ex.: versão do formato). */
        public Writer u8(int v) { out.write(v); return this; }

        public byte[] toBytes() { return out.toByteArray(); }
    }

    /** Lê o que o Writer escreveu. Lança IllegalArgumentException em dados malformados. */
    public static final class Reader {
        private final byte[] buf;
        private int pos = 0;

        public Reader(byte[] buf) { this.buf = buf; }

        private void need(int n) {
            if (n < 0 || pos + n > buf.length) {
                throw new IllegalArgumentException("dados truncados ou malformados");
            }
        }

        public byte[] field() {
            need(4);
            int len = toInt(buf, pos);
            pos += 4;
            if (len < 0 || len > MAX_FIELD) throw new IllegalArgumentException("comprimento inválido: " + len);
            need(len);
            byte[] out = new byte[len];
            System.arraycopy(buf, pos, out, 0, len);
            pos += len;
            return out;
        }

        public String string() { return utf8(field()); }

        public int integer() { need(4); int v = toInt(buf, pos); pos += 4; return v; }

        public long lng() { need(8); long v = toLong(buf, pos); pos += 8; return v; }

        public int u8() { need(1); return buf[pos++] & 0xFF; }

        public boolean atEnd() { return pos == buf.length; }

        /** Chamar no fim: rejeita bytes a mais (evita "dados ocultos" no fim de uma mensagem). */
        public void requireEnd() {
            if (!atEnd()) throw new IllegalArgumentException("bytes a mais no fim");
        }
    }
}