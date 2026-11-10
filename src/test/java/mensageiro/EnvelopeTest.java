package mensageiro;

import mensageiro.common.crypto.Bytes;
import mensageiro.common.crypto.Envelope;
import mensageiro.common.crypto.Envelope.InvalidEnvelopeException;
import mensageiro.common.crypto.Keys;

import java.security.KeyPair;
import java.security.Signature;
import java.util.Arrays;

import static mensageiro.Asserts.*;

public final class EnvelopeTest {

    /** Identidade de teste: um par de assinatura + um par de acordo de chaves. */
    private static final class Id {
        final String name;
        final KeyPair sign = Keys.generateSigning();
        final KeyPair agree = Keys.generateAgreement();
        Id(String name) { this.name = name; }
    }

    private static byte[] seal(byte[] msg, Id from, Id to) throws Exception {
        return Envelope.seal(msg, from.name, from.sign.getPrivate(), to.name, to.agree.getPublic());
    }

    private static Envelope.Opened open(byte[] env, Id from, Id to) throws Exception {
        return Envelope.open(env, from.name, from.sign.getPublic(), to.name, to.agree);
    }


    /** Envelope: ida e volta */
    static void testIdaEVolta() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob");
        byte[] msg = Bytes.utf8("olá Bob, este é um segredo");
        byte[] env = seal(msg, alice, bob);
        Envelope.Opened o = open(env, alice, bob);
        assertArrayEquals(msg, o.plaintext(), "texto");
        assertEquals("alice", o.senderId(), "remetente");
        assertEquals("bob", o.recipientId(), "destinatário");
    }

    /** Envelope: mensagem vazia e mensagem de 1 MiB */
    static void testMensagemVaziaE1MiB() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob");
        assertEquals(0, open(seal(new byte[0], alice, bob), alice, bob).plaintext().length, "vazia");
        byte[] big = new byte[1 << 20];
        new java.util.Random(1).nextBytes(big);
        assertArrayEquals(big, open(seal(big, alice, bob), alice, bob).plaintext(), "1 MiB");
    }

    /** Envelope: texto em claro não aparece no envelope */
    static void testTextoEmClaroNaoAparece() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob");
        byte[] msg = Bytes.utf8("SEGREDO-MUITO-ESPECIFICO");
        String hex = Bytes.toHex(seal(msg, alice, bob));
        assertTrue(!hex.contains(Bytes.toHex(msg)), "o texto não pode estar visível");
    }

    /** Envelope: dois envios iguais dão envelopes diferentes */
    static void testEnviosIguaisEnvelopesDiferentes() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob");
        byte[] msg = Bytes.utf8("igual");
        assertTrue(!Arrays.equals(seal(msg, alice, bob), seal(msg, alice, bob)), "devem diferir");
    }

    /** Envelope: peek devolve remetente e destinatário */
    static void testPeekDevolveIds() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob");
        Envelope.Header h = Envelope.peek(seal(Bytes.utf8("x"), alice, bob));
        assertEquals("alice", h.senderId(), "remetente");
        assertEquals("bob", h.recipientId(), "destinatário");
    }

    /** Envelope: terceiro (Carol) não consegue abrir */
    static void testTerceiroNaoConsegueAbrir() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob"), carol = new Id("carol");
        byte[] env = seal(Bytes.utf8("só para o Bob"), alice, bob);
        // Carol tenta abrir fingindo ser o Bob, com as suas próprias chaves
        assertThrows(InvalidEnvelopeException.class,
                () -> Envelope.open(env, "alice", alice.sign.getPublic(), "bob", carol.agree),
                "chave errada");
        // Carol tenta abrir com o seu próprio nome
        assertThrows(InvalidEnvelopeException.class, () -> open(env, alice, carol), "destinatário errado");
    }

    /** Envelope: assinatura de outra pessoa é rejeitada */
    static void testAssinaturaDeOutraPessoaRecusada() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob"), mallory = new Id("mallory");
        byte[] env = seal(Bytes.utf8("x"), alice, bob);
        assertThrows(InvalidEnvelopeException.class,
                () -> Envelope.open(env, "alice", mallory.sign.getPublic(), "bob", bob.agree),
                "chave de assinatura errada");
    }

    /** Envelope: remetente inesperado é rejeitado */
    static void testRemetenteInesperadoRecusado() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob");
        byte[] env = seal(Bytes.utf8("x"), alice, bob);
        assertThrows(InvalidEnvelopeException.class,
                () -> Envelope.open(env, "outra-pessoa", alice.sign.getPublic(), "bob", bob.agree),
                "remetente esperado diferente");
    }

    /** Envelope: alterar QUALQUER bit é detetado */
    static void testAlterarQualquerBitDetetado() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob");
        byte[] env = seal(Bytes.utf8("mensagem importante"), alice, bob);
        for (int i = 0; i < env.length; i++) {
            for (int bit = 0; bit < 8; bit += 7) { // bit 0 e bit 7 de cada byte
                byte[] t = env.clone();
                t[i] ^= (1 << bit);
                assertThrows(InvalidEnvelopeException.class, () -> open(t, alice, bob),
                        "alteração no byte " + i + " bit " + bit + " não foi detetada");
            }
        }
    }

    /** Envelope: truncado ou com bytes a mais é rejeitado */
    static void testTruncadoOuBytesAMaisRecusado() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob");
        byte[] env = seal(Bytes.utf8("x"), alice, bob);
        for (int n : new int[]{0, 1, 4, env.length / 2, env.length - 1}) {
            byte[] t = Arrays.copyOf(env, n);
            assertThrows(InvalidEnvelopeException.class, () -> open(t, alice, bob), "truncado a " + n);
        }
        byte[] extra = Bytes.concat(env, new byte[]{0});
        assertThrows(InvalidEnvelopeException.class, () -> open(extra, alice, bob), "bytes a mais");
    }

    /** Envelope: ninguém consegue reclamar a autoria (troca de remetente + nova assinatura) */
    static void testNinguemReclamaAutoria() throws Exception {
        Id alice = new Id("alice"), bob = new Id("bob"), mallory = new Id("mallory");
        byte[] env = seal(Bytes.utf8("mensagem da Alice"), alice, bob);

        // A Mallory desmonta o envelope, troca "alice" por "mallory" no cabeçalho e assina com a sua chave.
        Bytes.Reader r = new Bytes.Reader(env);
        Bytes.Reader b = new Bytes.Reader(r.field());
        Bytes.Reader h = new Bytes.Reader(b.field());
        byte[] nonce = b.field(), ct = b.field();
        int ver = h.u8(); h.string(); String rec = h.string();
        long ts = h.lng(); byte[] msgId = h.field(), eph = h.field();

        byte[] newHeader = new Bytes.Writer().u8(ver).string("mallory").string(rec)
                .lng(ts).field(msgId).field(eph).toBytes();
        byte[] newBody = new Bytes.Writer().field(newHeader).field(nonce).field(ct).toBytes();
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(mallory.sign.getPrivate());
        s.update(newBody);
        byte[] forged = new Bytes.Writer().field(newBody).field(s.sign()).toBytes();

        // A assinatura é válida, mas o cabeçalho está ligado à cifra (AAD), por isso a decifra falha.
        assertThrows(InvalidEnvelopeException.class, () -> open(forged, mallory, bob), "autoria forjada");
    }
}