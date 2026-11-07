package mensageiro;

import mensageiro.client.ClientSession;
import mensageiro.client.ClientSession.Received;
import mensageiro.client.keystore.Identity;
import mensageiro.client.keystore.KeyVault;
import mensageiro.common.crypto.Bytes;
import mensageiro.common.crypto.Keys;
import mensageiro.common.crypto.Proofs;
import mensageiro.common.crypto.Registration;
import mensageiro.common.protocol.Codec;
import mensageiro.common.protocol.Frame;
import mensageiro.common.protocol.MessageType;

import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static mensageiro.Asserts.*;

/** Testa o cliente de ponta a ponta contra o FakeRelay (clientes reais, sockets reais). */
public final class ClientFlowTest {

    /** Cliente de teste: sessão + filas de mensagens e avisos recebidos. */
    private static final class Client implements AutoCloseable {
        final ClientSession s;
        final Identity id;
        final BlockingQueue<Received> inbox = new LinkedBlockingQueue<>();
        final BlockingQueue<String> warnings = new LinkedBlockingQueue<>();

        Client(FakeRelay r, String userId) throws Exception {
            this(r, r.relayPub(), Identity.generate(userId), true);
        }
        Client(FakeRelay r, byte[] relayPubToTrust, Identity identity, boolean register) throws Exception {
            id = identity;
            s = new ClientSession("127.0.0.1", r.port(), relayPubToTrust, inbox::add, warnings::add);
            if (register) s.register(identity); else s.login(identity);
        }
        Received next() throws Exception { return inbox.poll(5, TimeUnit.SECONDS); }
        @Override public void close() { s.close(); }
    }

    // ------------------------------------------------------------------ Registration

    /** Registration: encode/decode e prova de posse */
    static void testRegistrationEncodeDecode() throws Exception {
        Identity a = Identity.generate("alice");
        var reg = new Registration("alice", a.signPublicEncoded(), a.agreePublicEncoded(), a.signRegister());
        assertTrue(reg.valid(), "registo válido");
        assertTrue(Registration.decode(reg.encode()).valid(), "válido depois de encode/decode");
    }

    /** Registration: chave de outra pessoa, id trocado ou chave X25519 trocada são recusados */
    static void testRegistrationAdulteradaRecusada() throws Exception {
        Identity a = Identity.generate("alice"), m = Identity.generate("mallory");
        byte[] sig = a.signRegister();
        assertTrue(!new Registration("alice", m.signPublicEncoded(), a.agreePublicEncoded(), sig).valid(), "chave de outra pessoa");
        assertTrue(!new Registration("bob", a.signPublicEncoded(), a.agreePublicEncoded(), sig).valid(), "id trocado");
        assertTrue(!new Registration("alice", a.signPublicEncoded(), m.agreePublicEncoded(), sig).valid(), "X25519 trocada");
    }

    /** Registration: ids inválidos recusados; payload com bytes a mais recusado */
    static void testRegistrationIdsEPayload() throws Exception {
        for (String bad : new String[]{"", "a b", "../x", "x".repeat(33), "ação"}) {
            assertTrue(!Registration.validUserId(bad), "devia recusar '" + bad + "'");
        }
        assertTrue(Registration.validUserId("ana_01-b.c"), "id válido");
        Identity a = Identity.generate("alice");
        byte[] ok = new Registration("alice", a.signPublicEncoded(), a.agreePublicEncoded(), a.signRegister()).encode();
        byte[] extra = java.util.Arrays.copyOf(ok, ok.length + 1);
        assertThrows(mensageiro.common.protocol.ProtocolException.class, () -> Registration.decode(extra), "bytes a mais");
    }

    /** Registration: impressão digital estável e dependente das duas chaves */
    static void testFingerprint() throws Exception {
        Identity a = Identity.generate("alice");
        var r1 = new Registration("alice", a.signPublicEncoded(), a.agreePublicEncoded(), new byte[0]);
        var r2 = new Registration("alice", a.signPublicEncoded(), Keys.encodePublic(Keys.generateAgreement().getPublic()), new byte[0]);
        assertEquals(r1.fingerprint(), r1.fingerprint(), "estável");
        assertTrue(!r1.fingerprint().equals(r2.fingerprint()), "muda com a chave X25519");
    }

    /** Proofs: assinatura do relay no desafio só vale para aquele utilizador e aquele nonce */
    static void testRelayChallenge() throws Exception {
        var relayKeys = Keys.generateSigning();
        byte[] pub = Keys.encodePublic(relayKeys.getPublic());
        byte[] nonce = new byte[32];
        new java.security.SecureRandom().nextBytes(nonce);
        java.security.Signature sg = java.security.Signature.getInstance("Ed25519");
        sg.initSign(relayKeys.getPrivate());
        sg.update(Proofs.msgRelayChallenge("alice", nonce));
        byte[] sig = sg.sign();
        assertTrue(Proofs.verifyRelayChallenge(pub, "alice", nonce, sig), "válida");
        assertTrue(!Proofs.verifyRelayChallenge(pub, "bob", nonce, sig), "outro utilizador");
        nonce[0] ^= 1;
        assertTrue(!Proofs.verifyRelayChallenge(pub, "alice", nonce, sig), "outro nonce (replay)");
        assertTrue(!Proofs.verifyRelayChallenge(Keys.encodePublic(Keys.generateSigning().getPublic()), "alice", nonce, sig), "outra chave");
    }

    // ------------------------------------------------------------------ fluxo completo

    /** Cliente: Alice envia, Bob recebe e decifra; o relay nunca vê o texto */
    static void testAliceEnviaBobRecebe() throws Exception {
        try (FakeRelay relay = new FakeRelay(); Client alice = new Client(relay, "alice"); Client bob = new Client(relay, "bob")) {
            String secret = "o segredo da logística é 4711";
            var l = alice.s.send("bob", secret);
            assertTrue(l.firstTime(), "primeira vez com o Bob");
            Received r = bob.next();
            assertTrue(r != null, "Bob devia receber");
            assertEquals("alice", r.from(), "remetente verificado");
            assertEquals(secret, r.text(), "texto");
            assertEquals(1, relay.seenEnvelopes.size(), "o relay viu 1 envelope");
            String hex = Bytes.toHex(relay.seenEnvelopes.get(0));
            assertTrue(hex.indexOf(Bytes.toHex(Bytes.utf8("4711"))) < 0, "texto em claro no relay!");
        }
    }

    /** Cliente: conversa nos dois sentidos */
    static void testDoisSentidos() throws Exception {
        try (FakeRelay relay = new FakeRelay(); Client alice = new Client(relay, "alice"); Client bob = new Client(relay, "bob")) {
            alice.s.send("bob", "olá");
            assertEquals("olá", bob.next().text(), "Bob recebeu");
            bob.s.send("alice", "olá de volta");
            assertEquals("olá de volta", alice.next().text(), "Alice recebeu");
        }
    }

    /** Cliente: relay que troca a chave X25519 do Bob na pesquisa é detetado */
    static void testRelayTrocaChave() throws Exception {
        try (FakeRelay relay = new FakeRelay(); Client alice = new Client(relay, "alice"); Client bob = new Client(relay, "bob")) {
            relay.tamperLookup = true;
            assertThrows(java.security.GeneralSecurityException.class,
                    () -> alice.s.send("bob", "isto não devia sair"), "prova de registo adulterada");
            assertEquals(0, relay.seenEnvelopes.size(), "nada foi enviado");
        }
    }

    /** Cliente: as chaves do contacto mudam (relay serve outras chaves válidas) -> recusado */
    static void testChavesMudam() throws Exception {
        try (FakeRelay relay = new FakeRelay(); Client alice = new Client(relay, "alice"); Client bob = new Client(relay, "bob")) {
            alice.s.send("bob", "primeira");
            bob.next();
            Identity other = Identity.generate("bob");
            relay.directory.put("bob", new Registration("bob", other.signPublicEncoded(),
                    other.agreePublicEncoded(), other.signRegister()));
            assertThrows(ClientSession.KeyChangedException.class,
                    () -> alice.s.send("bob", "segunda"), "mudança de chaves");
        }
    }

    /** Cliente: mensagem repetida pelo relay é descartada */
    static void testRepeticaoDescartada() throws Exception {
        try (FakeRelay relay = new FakeRelay(); Client alice = new Client(relay, "alice"); Client bob = new Client(relay, "bob")) {
            alice.s.send("bob", "uma vez só");
            assertEquals("uma vez só", bob.next().text(), "primeira entrega");
            relay.inject("bob", relay.seenEnvelopes.get(0));
            assertTrue(bob.warnings.poll(5, TimeUnit.SECONDS) != null, "aviso de repetição");
            assertTrue(bob.inbox.isEmpty(), "não pode aparecer duas vezes");
        }
    }

    /** Cliente: envelope destinado a outra pessoa é descartado */
    static void testEnvelopeDeOutro() throws Exception {
        try (FakeRelay relay = new FakeRelay(); Client alice = new Client(relay, "alice");
             Client bob = new Client(relay, "bob"); Client carol = new Client(relay, "carol")) {
            alice.s.send("bob", "só para o Bob");
            bob.next();
            relay.inject("carol", relay.seenEnvelopes.get(0)); // o relay tenta dá-lo à Carol
            assertTrue(carol.warnings.poll(5, TimeUnit.SECONDS) != null, "Carol devia receber um aviso");
            assertTrue(carol.inbox.isEmpty(), "Carol não pode ver nada");
        }
    }

    /** Cliente: um servidor que não é o relay esperado (chave diferente) é recusado na autenticação */
    static void testRelayFalso() throws Exception {
        try (FakeRelay real = new FakeRelay(); FakeRelay impostor = new FakeRelay()) {
            Identity a = Identity.generate("alice");
            // o cliente confia na chave do relay real, mas liga-se ao impostor
            ClientSession s = new ClientSession("127.0.0.1", impostor.port(), real.relayPub(), m -> { }, w -> { });
            try {
                assertThrows(java.security.GeneralSecurityException.class, () -> s.register(a), "relay falso");
            } finally {
                s.close();
            }
        }
    }

    /** Cliente: login com a identidade recuperada do cofre (palavra-passe certa) funciona; errada falha */
    static void testLoginComCofre() throws Exception {
        Path dir = Files.createTempDirectory("vaulttest");
        Path file = dir.resolve("alice.vault");
        char[] pw = "uma-palavra-passe-longa".toCharArray();
        try (FakeRelay relay = new FakeRelay(); Client bob = new Client(relay, "bob")) {
            Identity created = KeyVault.create(file, "alice", pw, 1000);
            try (Client first = new Client(relay, relay.relayPub(), created, true)) {
                first.s.send("bob", "da primeira sessão");
                assertEquals("da primeira sessão", bob.next().text(), "Bob recebeu");
            }
            assertThrows(KeyVault.VaultException.class,
                    () -> KeyVault.unlock(file, "palavra-errada".toCharArray()), "palavra-passe errada");
            Identity back = KeyVault.unlock(file, pw);
            try (Client again = new Client(relay, relay.relayPub(), back, false)) {
                bob.s.send("alice", "olá outra vez");
                assertEquals("olá outra vez", again.next().text(), "Alice voltou a receber");
                again.s.send("bob", "mesma identidade");
                assertEquals("mesma identidade", bob.next().text(), "Bob recebeu da identidade recuperada");
            }
        }
    }

    /** Cli: register cria o cofre e autentica; login volta a abrir o cofre; palavra-passe errada é recusada */
    static void testCliRegisterELogin() throws Exception {
        Path dir = Files.createTempDirectory("clitest");
        try (FakeRelay relay = new FakeRelay()) {
            String out1 = runCli(relay, dir, "register alice\npalavra-passe-1\nme\nquit\n");
            assertTrue(out1.contains("Registado e autenticado como 'alice'"), "register: " + out1);
            assertTrue(Files.exists(dir.resolve("alice.vault")), "cofre criado");

            String out2 = runCli(relay, dir, "login alice\npalavra-passe-1\nquit\n");
            assertTrue(out2.contains("Autenticado como 'alice'"), "login: " + out2);

            String out3 = runCli(relay, dir, "login alice\nerrada-errada\nquit\n");
            assertTrue(out3.contains("Cofre:") && !out3.contains("Autenticado como"), "login errado: " + out3);

            String out4 = runCli(relay, dir, "register alice\nquit\n");
            assertTrue(out4.contains("já existe um cofre"), "register repetido: " + out4);

            String out5 = runCli(relay, dir, "register bob\ncurta\nquit\n");
            assertTrue(out5.contains("demasiado curta") && !Files.exists(dir.resolve("bob.vault")), "palavra-passe curta: " + out5);
        }
    }

    private static String runCli(FakeRelay relay, Path vaultDir, String input) throws Exception {
        var in = new java.io.BufferedReader(new java.io.StringReader(input));
        var bytes = new java.io.ByteArrayOutputStream();
        var out = new java.io.PrintStream(bytes, true, java.nio.charset.StandardCharsets.UTF_8);
        new mensageiro.client.ui.Cli(in, out, "127.0.0.1", relay.port(), relay.relayPub(), vaultDir).run();
        return bytes.toString(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ relay (fake): sanity do protocolo

    /** Relay (fake): autenticação com chave errada é recusada */
    static void testAuthChaveErrada() throws Exception {
        try (FakeRelay relay = new FakeRelay(); Client alice = new Client(relay, "alice");
             Socket sock = new Socket("127.0.0.1", relay.port())) {
            var in = new java.io.BufferedInputStream(sock.getInputStream());
            var out = sock.getOutputStream();
            Frame.write(out, MessageType.AUTH_HELLO, new Codec.Writer().string("alice").toByteArray());
            Frame.Message ch = Frame.read(in);
            assertEquals(MessageType.CHALLENGE, ch.type(), "desafio recebido");
            byte[] nonce = new Codec.Reader(ch.payload()).bytes(128);
            byte[] sig = Identity.generate("alice").signAuth(nonce); // Mallory com outra chave
            Frame.write(out, MessageType.AUTH, new Codec.Writer().bytes(sig).toByteArray());
            assertEquals(MessageType.ERROR, Frame.read(in).type(), "Mallory não entra");
        }
    }

    /** Relay (fake): registo com prova de posse inválida é recusado */
    static void testRegistoProvaInvalida() throws Exception {
        try (FakeRelay relay = new FakeRelay(); Socket sock = new Socket("127.0.0.1", relay.port())) {
            Identity m = Identity.generate("mallory");
            var forged = new Registration("mallory", m.signPublicEncoded(), m.agreePublicEncoded(), new byte[64]);
            Frame.write(sock.getOutputStream(), MessageType.REGISTER, forged.encode());
            assertEquals(MessageType.ERROR, Frame.read(new java.io.BufferedInputStream(sock.getInputStream())).type(), "registo recusado");
        }
    }
}
