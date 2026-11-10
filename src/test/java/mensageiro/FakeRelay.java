package mensageiro;

import mensageiro.common.crypto.Envelope;
import mensageiro.common.crypto.Keys;
import mensageiro.common.crypto.Proofs;
import mensageiro.common.crypto.Registration;
import mensageiro.common.protocol.Codec;
import mensageiro.common.protocol.Frame;
import mensageiro.common.protocol.MessageType;
import mensageiro.relay.auth.RelayIdentity;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Relay mínimo SÓ PARA TESTES: permite testar o cliente sem depender do relay real (que ainda está em
 * construção). Segue o protocolo de docs/protocolo.md. Não guarda mensagens e não tem tokens.
 * Usa a RelayIdentity real do projeto para assinar o CHALLENGE.
 */
final class FakeRelay implements Closeable {

    final ServerSocket server;
    final RelayIdentity identity;
    final Map<String, Registration> directory = new ConcurrentHashMap<>();
    final Map<String, OutputStream> online = new ConcurrentHashMap<>();
    /** Tudo o que o relay viu passar em SEND (para verificar que nunca vê texto em claro). */
    final List<byte[]> seenEnvelopes = new CopyOnWriteArrayList<>();
    /** Se true, o relay adultera a chave X25519 nas respostas a LOOKUP (relay malicioso). */
    volatile boolean tamperLookup;
    private final SecureRandom rng = new SecureRandom();

    FakeRelay() throws Exception {
        identity = RelayIdentity.loadOrCreate(Files.createTempDirectory("fakerelay"));
        server = new ServerSocket(0);
        Thread t = new Thread(this::acceptLoop, "fake-relay");
        t.setDaemon(true);
        t.start();
    }

    int port() { return server.getLocalPort(); }
    byte[] relayPub() { return identity.publicKeyBytes(); }

    private void acceptLoop() {
        try {
            while (true) {
                Socket s = server.accept();
                Thread t = new Thread(() -> serve(s), "fake-relay-conn");
                t.setDaemon(true);
                t.start();
            }
        } catch (IOException ignored) { }
    }

    private static void error(OutputStream out, String msg) throws IOException {
        synchronized (out) { Frame.write(out, MessageType.ERROR, new Codec.Writer().u8(2).string(msg).toByteArray()); }
    }

    private static void reply(OutputStream out, MessageType t, byte[] payload) throws IOException {
        synchronized (out) { Frame.write(out, t, payload); }
    }

    /** Entrega diretamente um envelope a um utilizador ligado (usado para simular repetições). */
    void inject(String userId, byte[] envelope) throws IOException {
        OutputStream o = online.get(userId);
        if (o != null) reply(o, MessageType.DELIVER, envelope);
    }

    private void serve(Socket s) {
        String authedUser = null;
        String helloUser = null;
        byte[] nonce = null;
        try (s) {
            var in = new java.io.BufferedInputStream(s.getInputStream());
            var out = s.getOutputStream();
            Frame.Message m;
            while ((m = Frame.read(in)) != null) {
                try {
                    switch (m.type()) {
                        case REGISTER -> {
                            Registration reg = Registration.decode(m.payload());
                            if (!reg.valid()) { error(out, "registo inválido"); break; }
                            if (directory.putIfAbsent(reg.userId(), reg) != null) { error(out, "id já existe"); break; }
                            reply(out, MessageType.REGISTER_OK, new byte[0]);
                        }
                        case AUTH_HELLO -> {
                            helloUser = new Codec.Reader(m.payload()).string(Registration.MAX_ID);
                            if (!directory.containsKey(helloUser)) { error(out, "desconhecido"); break; }
                            nonce = new byte[32];
                            rng.nextBytes(nonce);
                            byte[] sig = identity.sign(Proofs.msgRelayChallenge(helloUser, nonce));
                            reply(out, MessageType.CHALLENGE, new Codec.Writer().bytes(nonce).bytes(sig).toByteArray());
                        }
                        case AUTH -> {
                            byte[] sig = new Codec.Reader(m.payload()).bytes(256);
                            Registration reg = helloUser == null ? null : directory.get(helloUser);
                            if (reg == null || nonce == null
                                    || !Proofs.verifyAuth(Keys.decodeSigningPublic(reg.signPub()), helloUser, nonce, sig)) {
                                error(out, "autenticação falhou");
                                break;
                            }
                            nonce = null; // desafio de uso único
                            authedUser = helloUser;
                            online.put(authedUser, out);
                            reply(out, MessageType.AUTH_OK, new byte[]{1});
                        }
                        case LOOKUP -> {
                            if (authedUser == null) { error(out, "não autenticado"); break; }
                            String id = new Codec.Reader(m.payload()).string(Registration.MAX_ID);
                            Registration reg = directory.get(id);
                            if (reg == null) { error(out, "utilizador não encontrado"); break; }
                            if (tamperLookup) {
                                reg = new Registration(reg.userId(), reg.signPub(),
                                        Keys.encodePublic(Keys.generateAgreement().getPublic()), reg.sig());
                            }
                            reply(out, MessageType.LOOKUP_OK, reg.encode());
                        }
                        case SEND -> {
                            if (authedUser == null) { error(out, "não autenticado"); break; }
                            var h = Envelope.peek(m.payload());
                            if (!h.senderId().equals(authedUser)) { error(out, "remetente não corresponde"); break; }
                            OutputStream dest = online.get(h.recipientId());
                            if (dest == null) { error(out, "destinatário offline"); break; }
                            seenEnvelopes.add(m.payload());
                            reply(dest, MessageType.DELIVER, m.payload());
                            reply(out, MessageType.SEND_OK, new byte[0]);
                        }
                        default -> error(out, "tipo não suportado");
                    }
                } catch (Exception e) {
                    error(out, "pedido inválido");
                }
            }
        } catch (IOException ignored) {
        } finally {
            if (authedUser != null) online.remove(authedUser);
        }
    }

    @Override
    public void close() throws IOException { server.close(); }
}
