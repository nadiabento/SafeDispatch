package mensageiro;

import mensageiro.common.crypto.Bytes;
import mensageiro.common.crypto.Kdf;

import static mensageiro.Asserts.*;

public final class BytesKdfTest {


    /** Bytes: int/long ida e volta */
    static void testIntLongIdaEVolta() throws Exception {
        assertEquals(123456789, Bytes.toInt(Bytes.fromInt(123456789), 0), "int");
        assertEquals(-1, Bytes.toInt(Bytes.fromInt(-1), 0), "int negativo");
        assertEquals(1L << 40, Bytes.toLong(Bytes.fromLong(1L << 40), 0), "long");
    }

    /** Bytes: hex ida e volta */
    static void testHexIdaEVolta() throws Exception {
        byte[] b = {0, 1, (byte) 0xAB, (byte) 0xFF};
        assertEquals("0001abff", Bytes.toHex(b), "toHex");
        assertArrayEquals(b, Bytes.fromHex("0001abff"), "fromHex");
    }

    /** Writer/Reader: ida e volta */
    static void testWriterReaderIdaEVolta() throws Exception {
        byte[] msg = new Bytes.Writer()
                .u8(1).string("alice").field(new byte[]{9, 8, 7}).lng(42L).integer(7).toBytes();
        Bytes.Reader r = new Bytes.Reader(msg);
        assertEquals(1, r.u8(), "u8");
        assertEquals("alice", r.string(), "string");
        assertArrayEquals(new byte[]{9, 8, 7}, r.field(), "field");
        assertEquals(42L, r.lng(), "long");
        assertEquals(7, r.integer(), "int");
        r.requireEnd();
    }

    /** Writer: sem ambiguidade (ab,c) != (a,bc) */
    static void testWriterSemAmbiguidade() throws Exception {
        byte[] x = new Bytes.Writer().string("ab").string("c").toBytes();
        byte[] y = new Bytes.Writer().string("a").string("bc").toBytes();
        assertTrue(!java.util.Arrays.equals(x, y), "devem ser diferentes");
    }

    /** Reader: rejeita dados truncados */
    static void testReaderRejeitaTruncados() throws Exception {
        byte[] msg = new Bytes.Writer().string("alice").toBytes();
        byte[] cut = java.util.Arrays.copyOf(msg, msg.length - 1);
        assertThrows(IllegalArgumentException.class, () -> new Bytes.Reader(cut).string(), "truncado");
    }

    /** Reader: rejeita comprimento gigante */
    static void testReaderRejeitaComprimentoGigante() throws Exception {
        byte[] evil = Bytes.fromInt(Integer.MAX_VALUE);
        assertThrows(IllegalArgumentException.class, () -> new Bytes.Reader(evil).field(), "gigante");
    }

    /** Reader: rejeita comprimento negativo */
    static void testReaderRejeitaComprimentoNegativo() throws Exception {
        byte[] evil = Bytes.fromInt(-5);
        assertThrows(IllegalArgumentException.class, () -> new Bytes.Reader(evil).field(), "negativo");
    }

    /** Reader: requireEnd rejeita bytes a mais */
    static void testReaderRequireEndRejeitaBytesAMais() throws Exception {
        byte[] msg = Bytes.concat(new Bytes.Writer().string("a").toBytes(), new byte[]{1});
        Bytes.Reader r = new Bytes.Reader(msg);
        r.string();
        assertThrows(IllegalArgumentException.class, r::requireEnd, "bytes a mais");
    }

    // ---- HKDF: vetores de teste oficiais da RFC 5869 ----

    /** HKDF: RFC 5869 caso 1 */
    static void testHkdfRfc5869Caso1() throws Exception {
        byte[] ikm  = Bytes.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = Bytes.fromHex("000102030405060708090a0b0c");
        byte[] info = Bytes.fromHex("f0f1f2f3f4f5f6f7f8f9");
        byte[] prk = Kdf.hkdfExtract(salt, ikm);
        assertEquals("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                Bytes.toHex(prk), "PRK");
        byte[] okm = Kdf.hkdfExpand(prk, info, 42);
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                Bytes.toHex(okm), "OKM");
    }

    /** HKDF: RFC 5869 caso 3 (sem salt, sem info) */
    static void testHkdfRfc5869Caso3() throws Exception {
        byte[] ikm = Bytes.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] okm = Kdf.hkdf(null, ikm, new byte[0], 42);
        assertEquals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                Bytes.toHex(okm), "OKM");
    }

    /** HKDF: 'info' diferente dá chaves diferentes */
    static void testHkdfInfoDiferenteChavesDiferentes() throws Exception {
        byte[] ikm = new byte[32];
        byte[] a = Kdf.hkdf(null, ikm, Bytes.utf8("cifra"), 32);
        byte[] b = Kdf.hkdf(null, ikm, Bytes.utf8("mac"), 32);
        assertTrue(!java.util.Arrays.equals(a, b), "separação de domínios");
    }
}