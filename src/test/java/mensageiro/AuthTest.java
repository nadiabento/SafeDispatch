package mensageiro;

import mensageiro.common.crypto.Proofs;
import mensageiro.common.protocol.*;
import mensageiro.relay.RelayServer;
import mensageiro.relay.auth.RelayIdentity;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Testes do relay com um servidor e clientes REAIS (sockets TCP numa porta livre).
 * Cada teste arranca o seu próprio relay, com identidade nova.
 */
public final class AuthTest {

    private static void check(boolean c, String m) { if (!c) throw new AssertionError(m); }
    private static final SecureRandom RANDOM = new SecureRandom();

    // ---------- auxiliares: um mini-cliente de teste ----------
    private static final class Cliente implements AutoCloseable {
        final Socket socket;
        final InputStream in;
        final OutputStream out;
        final String user;
        final KeyPair sign, kex;

        Cliente(int porta, String user) throws Exception {
            socket = new Socket("127.0.0.1", porta);
            socket.setSoTimeout(5000);                      // um teste nunca fica pendurado
            in = socket.getInputStream();
            out = socket.getOutputStream();
            this.user = user;
            sign = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            kex = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        }
        void enviar(MessageType t, byte[] payload) throws IOException { Frame.write(out, t, payload); }
        Frame.Message receber() throws IOException { return Frame.read(in); }
        @Override public void close() throws IOException { socket.close(); }

        /** REGISTER com a prova assinada por 'chaveProva' (a do cliente, ou outra, para testar fraudes). */
        Frame.Message registar(KeyPair chaveProva) throws Exception {
            byte[] ps = sign.getPublic().getEncoded(), pk = kex.getPublic().getEncoded();
            byte[] prova = Proofs.signRegister(chaveProva.getPrivate(), user, ps, pk);
            enviar(MessageType.REGISTER, new Codec.Writer().string(user).bytes(ps).bytes(pk).bytes(prova).toByteArray());
            return receber();
        }
        Frame.Message registar() throws Exception { return registar(sign); }

        /** Handshake completo. Devolve a resposta final (AUTH_OK ou ERROR). */
        Frame.Message autenticar(byte[] relayPub) throws Exception {
            enviar(MessageType.AUTH_HELLO, new Codec.Writer().string(user).toByteArray());
            var ch = receber();
            check(ch.type() == MessageType.CHALLENGE, "esperava CHALLENGE, veio " + ch.type());
            var r = new Codec.Reader(ch.payload());
            byte[] nonce = r.bytes(64), sigRelay = r.bytes(128);
            // O CLIENTE verifica que o relay é o verdadeiro (é o que impede um relay falso)
            check(Proofs.verifyRelayChallenge(relayPub, user, nonce, sigRelay), "assinatura do relay inválida");
            byte[] sig = Proofs.signAuth(sign.getPrivate(), user, nonce);
            enviar(MessageType.AUTH, new Codec.Writer().bytes(sig).toByteArray());
            return receber();
        }
    }

    private static RelayIdentity novaIdentidade() throws Exception {
        return RelayIdentity.loadOrCreate(Files.createTempDirectory("relay"));
    }

    private static void esperaErro(Frame.Message m, String quando) {
        check(m != null && m.type() == MessageType.ERROR, quando + ": esperava ERROR, veio " + (m == null ? "nada" : m.type()));
    }

    // ---------- testes ----------

    // Registo + autenticação mútua completa (o cliente verifica o relay, o relay verifica o cliente)
    static void testRegistoEAutenticacao() throws Exception {
        var id = novaIdentidade();
        try (var relay = new RelayServer(id)) {
            int porta = relay.start(0);
            try (var alice = new Cliente(porta, "alice")) {
                check(alice.registar().type() == MessageType.REGISTER_OK, "registo devia ser aceite");
                check(alice.autenticar(id.publicKeyBytes()).type() == MessageType.AUTH_OK, "autenticação devia ser aceite");
            }
        }
    }

    // Quem regista com a assinatura de OUTRA chave (não tem a chave privada) é recusado
    static void testRegistoSemProvaDePosseRecusado() throws Exception {
        try (var relay = new RelayServer(novaIdentidade())) {
            int porta = relay.start(0);
            try (var mallory = new Cliente(porta, "mallory")) {
                var outraChave = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
                esperaErro(mallory.registar(outraChave), "prova com outra chave");
            }
        }
    }

    // Um nome já registado não pode ser registado outra vez com outras chaves
    static void testNomeRepetidoRecusado() throws Exception {
        try (var relay = new RelayServer(novaIdentidade())) {
            int porta = relay.start(0);
            try (var a = new Cliente(porta, "alice"); var intruso = new Cliente(porta, "alice")) {
                check(a.registar().type() == MessageType.REGISTER_OK, "1.º registo");
                esperaErro(intruso.registar(), "2.º registo com o mesmo nome");
            }
        }
    }

    // Nomes inválidos são recusados
    static void testNomeInvalidoRecusado() throws Exception {
        try (var relay = new RelayServer(novaIdentidade())) {
            int porta = relay.start(0);
            try (var c = new Cliente(porta, "Ana Maria!")) {
                esperaErro(c.registar(), "nome inválido");
            }
        }
    }

    // Relay falso (outras chaves): o cliente deteta que a assinatura do desafio não verifica
    static void testRelayFalsoDetetadoPeloCliente() throws Exception {
        var falso = novaIdentidade();
        var verdadeiro = novaIdentidade();
        try (var relayFalso = new RelayServer(falso)) {
            int porta = relayFalso.start(0);
            try (var alice = new Cliente(porta, "alice")) {
                alice.registar();
                boolean detetado = false;
                try {
                    // O cliente tem a chave do relay VERDADEIRO, mas está a falar com o falso
                    alice.autenticar(verdadeiro.publicKeyBytes());
                } catch (AssertionError e) {
                    detetado = e.getMessage().contains("assinatura do relay inválida");
                }
                check(detetado, "o cliente devia ter detetado o relay falso");
            }
        }
    }

    // Quem responde ao desafio com uma chave que não é a do utilizador é recusado
    static void testAutenticacaoComChaveErradaRecusada() throws Exception {
        var id = novaIdentidade();
        try (var relay = new RelayServer(id)) {
            int porta = relay.start(0);
            try (var alice = new Cliente(porta, "alice"); var intruso = new Cliente(porta, "alice")) {
                alice.registar();
                // O intruso conhece o nome "alice" mas não tem a chave privada dela
                var resp = intruso.autenticar(id.publicKeyBytes());
                esperaErro(resp, "autenticação com chave errada");
            }
        }
    }

    // Replay: a resposta (válida) de uma ligação antiga não serve numa ligação nova
    static void testReplayDaAutenticacaoRecusado() throws Exception {
        var id = novaIdentidade();
        try (var relay = new RelayServer(id)) {
            int porta = relay.start(0);

            byte[] sigAntiga, nonce1;
            try (var alice = new Cliente(porta, "alice")) {
                alice.registar();
                alice.enviar(MessageType.AUTH_HELLO, new Codec.Writer().string("alice").toByteArray());
                nonce1 = new Codec.Reader(alice.receber().payload()).bytes(64);
                sigAntiga = Proofs.signAuth(alice.sign.getPrivate(), "alice", nonce1);
                alice.enviar(MessageType.AUTH, new Codec.Writer().bytes(sigAntiga).toByteArray());
                check(alice.receber().type() == MessageType.AUTH_OK, "a ligação legítima devia autenticar");
            }
            // Um atacante captura sigAntiga e tenta reutilizá-la numa ligação nova
            try (var atacante = new Cliente(porta, "alice")) {
                atacante.enviar(MessageType.AUTH_HELLO, new Codec.Writer().string("alice").toByteArray());
                byte[] nonce2 = new Codec.Reader(atacante.receber().payload()).bytes(64);
                check(!Arrays.equals(nonce1, nonce2), "o relay devia usar um nonce novo em cada ligação");
                atacante.enviar(MessageType.AUTH, new Codec.Writer().bytes(sigAntiga).toByteArray());
                esperaErro(atacante.receber(), "replay da autenticação");
            }
        }
    }

    // Sem autenticação não se envia nem se pesquisa
    static void testSemAutenticacaoRecusado() throws Exception {
        try (var relay = new RelayServer(novaIdentidade())) {
            int porta = relay.start(0);
            try (var c = new Cliente(porta, "alice")) {
                c.registar();
                c.enviar(MessageType.SEND, new Codec.Writer().string("bob").bytes(new byte[]{1}).toByteArray());
                esperaErro(c.receber(), "SEND sem autenticação");
                c.enviar(MessageType.LOOKUP, new Codec.Writer().string("bob").toByteArray());
                esperaErro(c.receber(), "LOOKUP sem autenticação");
            }
        }
    }

    // Descoberta + envio entre dois clientes; o relay indica o remetente AUTENTICADO e não altera o envelope
    static void testDescobertaEEnvioEntreDoisClientes() throws Exception {
        var id = novaIdentidade();
        try (var relay = new RelayServer(id)) {
            int porta = relay.start(0);
            try (var alice = new Cliente(porta, "alice"); var bob = new Cliente(porta, "bob")) {
                alice.registar(); bob.registar();
                check(alice.autenticar(id.publicKeyBytes()).type() == MessageType.AUTH_OK, "alice autentica");
                check(bob.autenticar(id.publicKeyBytes()).type() == MessageType.AUTH_OK, "bob autentica");

                // Descoberta: a alice obtém as chaves do bob
                alice.enviar(MessageType.LOOKUP, new Codec.Writer().string("bob").toByteArray());
                var lk = alice.receber();
                check(lk.type() == MessageType.LOOKUP_OK, "lookup");
                var r = new Codec.Reader(lk.payload());
                String nome = r.string(32); byte[] ps = r.bytes(128), pk = r.bytes(128);
                check(nome.equals("bob") && Arrays.equals(ps, bob.sign.getPublic().getEncoded()), "chaves do bob");
                check(Arrays.equals(pk, bob.kex.getPublic().getEncoded()), "chave de acordo do bob");

                // Envio: bytes opacos que o relay não pode alterar
                byte[] envelope = new byte[300];
                RANDOM.nextBytes(envelope);
                alice.enviar(MessageType.SEND, new Codec.Writer().string("bob").bytes(envelope).toByteArray());
                var ok = alice.receber();
                check(ok.type() == MessageType.SEND_OK, "SEND_OK");

                var entrega = bob.receber();
                check(entrega.type() == MessageType.DELIVER, "bob devia receber DELIVER");
                var d = new Codec.Reader(entrega.payload());
                check(d.string(32).equals("alice"), "o remetente tem de ser o utilizador autenticado");
                d.bytes(16);
                check(Arrays.equals(envelope, d.bytes(1 << 20)), "o envelope devia chegar intacto");
            }
        }
    }

    // Enviar para um utilizador desconhecido/offline dá erro (o armazenamento diferido é da Entrega 2)
    static void testDestinatarioOfflineDaErro() throws Exception {
        var id = novaIdentidade();
        try (var relay = new RelayServer(id)) {
            int porta = relay.start(0);
            try (var alice = new Cliente(porta, "alice")) {
                alice.registar();
                alice.autenticar(id.publicKeyBytes());
                alice.enviar(MessageType.SEND, new Codec.Writer().string("ninguem").bytes(new byte[]{1}).toByteArray());
                esperaErro(alice.receber(), "destinatário inexistente");
            }
        }
    }

    // Frame com comprimento de 2 GB: o relay responde ERROR e fecha, sem tentar reservar a memória
    static void testFrameGiganteFechaALigacao() throws Exception {
        try (var relay = new RelayServer(novaIdentidade())) {
            int porta = relay.start(0);
            try (var c = new Cliente(porta, "alice")) {
                c.out.write(new byte[]{0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 9});
                c.out.flush();
                esperaErro(c.receber(), "frame gigante");
                try { check(c.receber() == null, "a ligação devia ter sido fechada"); }
                catch (IOException fechada) { /* reset da ligação: também conta como fechada */ }
            }
        }
    }

    // Vários clientes ao mesmo tempo: nenhum bloqueia os outros
    static void testVariosClientesEmSimultaneo() throws Exception {
        var id = novaIdentidade();
        try (var relay = new RelayServer(id)) {
            int porta = relay.start(0);
            int n = 20;
            var falhas = new java.util.concurrent.ConcurrentLinkedQueue<Throwable>();
            var threads = new Thread[n];
            for (int i = 0; i < n; i++) {
                final String nome = "user" + i;
                threads[i] = new Thread(() -> {
                    try (var c = new Cliente(porta, nome)) {
                        check(c.registar().type() == MessageType.REGISTER_OK, "registo " + nome);
                        check(c.autenticar(id.publicKeyBytes()).type() == MessageType.AUTH_OK, "auth " + nome);
                    } catch (Throwable t) { falhas.add(t); }
                });
                threads[i].start();
            }
            for (var t : threads) t.join(15000);
            check(falhas.isEmpty(), "falhas em clientes simultâneos: " + falhas);
        }
    }
}