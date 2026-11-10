package mensageiro.client;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Consumer;
import mensageiro.client.keystore.Identity;
import mensageiro.client.net.RelayConnection;
import mensageiro.client.trust.Contacts;
import mensageiro.common.crypto.Bytes;
import mensageiro.common.crypto.Envelope;
import mensageiro.common.crypto.Keys;
import mensageiro.common.crypto.Proofs;
import mensageiro.common.crypto.Registration;
import mensageiro.common.protocol.Codec;
import mensageiro.common.protocol.Frame;
import mensageiro.common.protocol.MessageType;

/**
 * Lógica do cliente: registar, autenticar, pesquisar, enviar e receber mensagens E2E.
 * Não sabe nada de consola (isso é a Cli) nem de onde vêm as chaves (isso é o KeyVault):
 * recebe uma Identity já desbloqueada.
 */
public final class ClientSession implements Closeable {

    public record Received(String from, String text, long timestamp) {}

    /** O relay devolveu para um utilizador chaves diferentes das que já conhecíamos. */
    public static final class KeyChangedException extends GeneralSecurityException {
        public KeyChangedException(String m) { super(m); }
    }

    /** Resultado de uma pesquisa: o contacto verificado e se é a primeira vez que o vemos. */
    public record Lookup(Registration contact, boolean firstTime, String fingerprint) {}

    private final RelayConnection conn;
    private final byte[] relayPub;        // chave pública do relay (relay.pub), obtida por um canal de confiança
    private final Contacts contacts = new Contacts();
    private final Consumer<Received> onMessage;
    private final Consumer<String> onWarning;
    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    // As mensagens recebidas são processadas fora da thread de leitura: abrir uma exige uma pesquisa
    // ao relay, e essa pesquisa precisa que a thread de leitura continue a correr.
    private final ExecutorService inbox = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "inbox");
        t.setDaemon(true);
        return t;
    });

    private volatile Identity me;
    private volatile byte[] token; // credencial devolvida pelo relay (opaca; o Módulo C define o formato)

    public ClientSession(String host, int port, byte[] relayPub,
                         Consumer<Received> onMessage, Consumer<String> onWarning) throws IOException {
        this.relayPub = relayPub.clone();
        this.onMessage = onMessage;
        this.onWarning = onWarning;
        this.conn = new RelayConnection(host, port, env -> {
            try {
                inbox.execute(() -> handleDeliver(env));
            } catch (RejectedExecutionException closing) {
                // a sessão está a fechar: ignorar entregas tardias
            }
        });
    }

    // ---------------- registo e autenticação ----------------

    /** Primeira vez: regista a identidade no relay e autentica-se. */
    public void register(Identity id) throws IOException, GeneralSecurityException {
        if (!Registration.validUserId(id.userId)) {
            throw new IllegalArgumentException("id inválido (use 1 a 32 letras, dígitos, '.', '_' ou '-')");
        }
        Registration reg = new Registration(id.userId, id.signPublicEncoded(), id.agreePublicEncoded(), id.signRegister());
        conn.request(MessageType.REGISTER, reg.encode(), MessageType.REGISTER_OK);
        authenticate(id);
    }

    /** Já registado (identidade vinda do cofre): só autentica. */
    public void login(Identity id) throws IOException, GeneralSecurityException {
        authenticate(id);
    }

    /**
     * Autenticação nos dois sentidos:
     *  1. o relay manda um nonce e a sua assinatura; o cliente verifica-a com a relay.pub (é o relay verdadeiro?);
     *  2. o cliente assina o nonce com a sua chave Ed25519 (é o utilizador verdadeiro?).
     */
    private void authenticate(Identity id) throws IOException, GeneralSecurityException {
        Frame.Message ch = conn.request(MessageType.AUTH_HELLO,
                new Codec.Writer().string(id.userId).toByteArray(), MessageType.CHALLENGE);
        Codec.Reader r = new Codec.Reader(ch.payload());
        byte[] nonce = r.bytes(128);
        byte[] relaySig = r.bytes(256);
        r.end();
        if (nonce.length < 16) throw new GeneralSecurityException("desafio demasiado curto");
        if (!Proofs.verifyRelayChallenge(relayPub, id.userId, nonce, relaySig)) {
            throw new GeneralSecurityException(
                    "o servidor NÃO é o relay esperado (assinatura inválida): autenticação cancelada");
        }

        byte[] sig = id.signAuth(nonce);
        Frame.Message ok = conn.request(MessageType.AUTH, new Codec.Writer().bytes(sig).toByteArray(), MessageType.AUTH_OK);
        this.me = id;
        this.token = ok.payload();
    }

    // ---------------- pesquisa ----------------

    public Lookup lookup(String userId) throws IOException, GeneralSecurityException {
        Frame.Message m = conn.request(MessageType.LOOKUP,
                new Codec.Writer().string(userId).toByteArray(), MessageType.LOOKUP_OK);
        Registration reg = Registration.decode(m.payload());

        // não confiamos no relay: a entrada tem de ser a do utilizador pedido e a prova tem de ser válida
        if (!reg.userId().equals(userId)) throw new GeneralSecurityException("o relay devolveu outro utilizador");
        if (!reg.valid()) throw new GeneralSecurityException("prova de registo inválida");

        String fp = reg.fingerprint();
        return switch (contacts.pin(reg)) {
            case NEW -> new Lookup(reg, true, fp);
            case KNOWN -> new Lookup(reg, false, fp);
            case CHANGED -> throw new KeyChangedException(
                    "as chaves de '" + userId + "' mudaram desde a última vez. Recusado (possível ataque).");
        };
    }

    // ---------------- enviar ----------------

    public Lookup send(String to, String text) throws IOException, GeneralSecurityException {
        Identity id = requireMe();
        Lookup l = lookup(to);
        byte[] env = Envelope.seal(text.getBytes(StandardCharsets.UTF_8),
                id.userId, id.signKeys.getPrivate(),
                to, Keys.decodeAgreementPublic(l.contact().agreePub()));
        conn.request(MessageType.SEND, env, MessageType.SEND_OK);
        return l;
    }

    // ---------------- receber ----------------

    private void handleDeliver(byte[] envelope) {
        try {
            Identity id = requireMe();
            Envelope.Header h = Envelope.peek(envelope); // só para saber a quem pedir a chave; nada é confiável ainda
            Lookup l = lookup(h.senderId());
            Envelope.Opened o = Envelope.open(envelope, h.senderId(),
                    Keys.decodeSigningPublic(l.contact().signPub()), id.userId, id.agreeKeys);
            if (!seen.add(Bytes.toHex(o.msgId()))) {
                onWarning.accept("mensagem repetida descartada (msgId já visto)");
                return;
            }
            if (l.firstTime()) {
                onWarning.accept("primeira mensagem de '" + h.senderId()
                        + "'. Confirme a impressão digital por outro canal: " + l.fingerprint());
            }
            onMessage.accept(new Received(o.senderId(), new String(o.plaintext(), StandardCharsets.UTF_8), o.timestamp()));
        } catch (Exception e) {
            // uma mensagem inválida é simplesmente descartada
            onWarning.accept("mensagem recebida descartada: " + e.getMessage());
        }
    }

    // ---------------- utilitários ----------------

    public String myFingerprint() {
        Identity id = requireMe();
        return new Registration(id.userId, id.signPublicEncoded(), id.agreePublicEncoded(), new byte[0]).fingerprint();
    }

    public String myId() { return requireMe().userId; }

      /** Credencial devolvida pelo relay no login (opaca; o Módulo C define o formato). */
  public byte[] token() { byte[] t = token; return t == null ? null : t.clone(); }
  
    private Identity requireMe() {
        Identity id = me;
        if (id == null) throw new IllegalStateException("ainda não autenticou (use: register <id> ou login <id>)");
        return id;
    }

    @Override
    public void close() {
        inbox.shutdownNow();
        conn.close();
    }
}
