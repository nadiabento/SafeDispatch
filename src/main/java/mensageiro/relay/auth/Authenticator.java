package mensageiro.relay.auth;

import mensageiro.common.crypto.Keys;
import mensageiro.common.crypto.Proofs;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Registo e autenticação (o relay prova quem é, o cliente prova quem é).
 * Usa o Proofs (da Jessica) para saber O QUE se assina e como se verifica.
 *
 * Registo:  o cliente envia nome + chaves + assinatura de posse. O relay verifica a assinatura
 *           com a própria chave pública enviada (prova que o cliente tem a chave privada).
 *
 * Handshake (por ligação):
 *   C -> R  AUTH_HELLO(user)
 *   R -> C  CHALLENGE(nonce, Assina_relay(msgRelayChallenge(user, nonce)))  <- o cliente verifica o relay
 *   C -> R  AUTH(Assina_user(msgAuth(user, nonce)))                         <- o relay verifica o cliente
 * O nonce é novo e aleatório em cada ligação, por isso uma resposta antiga não serve.
 */
public final class Authenticator {
    /** Tempo máximo entre o desafio e a resposta. */
    static final long VALIDADE_DESAFIO_MS = 30_000;

    private final Directory directory;
    private final RelayIdentity relay;
    private final SecureRandom random = new SecureRandom();

    /** Desafio enviado a um cliente. Cada ligação guarda o seu e só o pode usar uma vez. */
    public record Desafio(String utilizador, byte[] nonce, byte[] assinaturaRelay, long emitidoEm) {}

    public Authenticator(Directory directory, RelayIdentity relay) {
        this.directory = directory;
        this.relay = relay;
    }

    public Directory directory() { return directory; }

    /**
     * Regista um utilizador. Devolve false se for recusado: nome inválido ou já usado,
     * chaves inválidas ou prova de posse falsa.
     */
    public boolean registar(String user, byte[] pubSign, byte[] pubKex, byte[] prova) {
        if (!Directory.nomeValido(user)) return false;
        // verifyRegister valida as duas chaves e verifica a assinatura com a chave enviada
        if (!Proofs.verifyRegister(user, pubSign, pubKex, prova)) return false;
        return directory.adicionar(new Directory.Entry(user, pubSign, pubKex));
    }

    /** Passo 1 do handshake. Devolve null se o utilizador não existir. */
    public Desafio iniciar(String user) {
        if (directory.procurar(user) == null) return null;
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        byte[] assinatura = assinarRelay(Proofs.msgRelayChallenge(user, nonce));
        return new Desafio(user, nonce, assinatura, System.currentTimeMillis());
    }

    /** Passo 2: verifica a resposta do cliente com a chave pública registada para esse nome. */
    public boolean concluir(Desafio d, byte[] assinaturaCliente) {
        if (System.currentTimeMillis() - d.emitidoEm() > VALIDADE_DESAFIO_MS) return false; // expirou
        Directory.Entry e = directory.procurar(d.utilizador());
        if (e == null) return false;
        try {
            PublicKey pk = Keys.decodeSigningPublic(e.pubSign());
            return Proofs.verifyAuth(pk, d.utilizador(), d.nonce(), assinaturaCliente);
        } catch (GeneralSecurityException | RuntimeException ex) {
            return false;
        }
    }

    private byte[] assinarRelay(byte[] msg) {
        try {
            return relay.sign(msg);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("o relay não conseguiu assinar", e); // erro do servidor
        }
    }
}