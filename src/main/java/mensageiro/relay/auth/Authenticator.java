package mensageiro.relay.auth;

import mensageiro.common.crypto.Proofs;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Registo e autenticação mútua (o relay prova quem é, o cliente prova quem é).
 *
 * Registo:  o cliente envia nome + chaves + assinatura de posse. O relay verifica a assinatura
 *           com a própria chave pública enviada (prova que o cliente tem a chave privada).
 *
 * Handshake (por ligação):
 *   C -> R  AUTH_HELLO(user, nonceCliente)
 *   R -> C  CHALLENGE(nonceRelay, Assina_relay(nonceCliente, nonceRelay, user))   <- o cliente verifica o relay
 *   C -> R  AUTH(Assina_user(nonceCliente, nonceRelay, user))                      <- o relay verifica o cliente
 * Os dois nonces são novos em cada ligação, por isso uma resposta antiga não serve (replay).
 */
public final class Authenticator {
    /** Tempo máximo entre o desafio e a resposta. */
    static final long VALIDADE_DESAFIO_MS = 30_000;

    private final Directory directory;
    private final RelayIdentity relay;
    private final SecureRandom random = new SecureRandom();

    /** Desafio enviado a um cliente. Cada ligação guarda o seu e só o pode usar uma vez. */
    public record Desafio(String utilizador, byte[] nonceCliente, byte[] nonceRelay,
                          byte[] assinaturaRelay, long emitidoEm) {}

    public Authenticator(Directory directory, RelayIdentity relay) {
        this.directory = directory;
        this.relay = relay;
    }

    public Directory directory() { return directory; }

    /**
     * Regista um utilizador. Devolve o certificado do relay (a sua assinatura sobre nome+chaves),
     * ou null se o registo for recusado (nome inválido ou já usado, chaves inválidas, prova falsa).
     */
    public byte[] registar(String user, byte[] pubSign, byte[] pubKex, byte[] prova) {
        if (!Directory.nomeValido(user)) return null;
        if (!Directory.chavesValidas(pubSign, pubKex)) return null;
        // A prova tem de verificar com a chave pública que o próprio cliente enviou
        if (!Proofs.verify(pubSign, Proofs.registerMsg(user, pubSign, pubKex), prova)) return null;
        if (!directory.adicionar(new Directory.Entry(user, pubSign, pubKex))) return null;
        return certificado(user, pubSign, pubKex);
    }

    /** Certificado: o relay assina "este utilizador tem estas chaves". */
    public byte[] certificado(String user, byte[] pubSign, byte[] pubKex) {
        return assinarRelay(Proofs.certMsg(user, pubSign, pubKex));
    }

    /** Passo 1 do handshake. Devolve null se o utilizador não existir. */
    public Desafio iniciar(String user, byte[] nonceCliente) {
        if (directory.procurar(user) == null) return null;
        byte[] nonceRelay = new byte[32];
        random.nextBytes(nonceRelay);
        byte[] assinatura = assinarRelay(Proofs.srvMsg(nonceCliente, nonceRelay, user));
        return new Desafio(user, nonceCliente, nonceRelay, assinatura, System.currentTimeMillis());
    }

    /** Passo 2: verifica a resposta do cliente com a chave pública registada para esse nome. */
    public boolean concluir(Desafio d, byte[] assinaturaCliente) {
        if (System.currentTimeMillis() - d.emitidoEm() > VALIDADE_DESAFIO_MS) return false; // expirou
        Directory.Entry e = directory.procurar(d.utilizador());
        if (e == null) return false;
        byte[] msg = Proofs.authMsg(d.nonceCliente(), d.nonceRelay(), d.utilizador());
        return Proofs.verify(e.pubSign(), msg, assinaturaCliente);
    }

    private byte[] assinarRelay(byte[] msg) {
        try {
            return relay.sign(msg);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("o relay não conseguiu assinar", e); // erro do servidor, não do cliente
        }
    }
}