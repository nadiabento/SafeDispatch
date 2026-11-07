package mensageiro.common.crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Assinaturas usadas no REGISTER e no AUTH.
 *
 * O cliente assina com Ed25519 e o relay verifica. Para os dois lados concordarem sobre
 * "o que foi assinado", ambos constroem os bytes pelas MESMAS funções (msgRegister/msgAuth).
 *
 * Cada tipo de prova tem uma etiqueta própria (separação de domínios): uma assinatura de
 * REGISTER nunca pode ser reaproveitada como assinatura de AUTH, e vice-versa.
 */
public final class Proofs {

    private Proofs() {}

    private static final byte[] LABEL_REGISTER = Bytes.utf8("SafeDispatch/register/v1");
    private static final byte[] LABEL_AUTH = Bytes.utf8("SafeDispatch/auth/v1");
    private static final byte[] LABEL_RELAY = Bytes.utf8("SafeDispatch/relay-challenge/v1");

    // ---------------- bytes que são assinados ----------------

    /** REGISTER: prova de posse da chave privada Ed25519 (liga o userId às duas chaves públicas). */
    public static byte[] msgRegister(String userId, byte[] signPubEnc, byte[] agreePubEnc) {
        return new Bytes.Writer()
                .field(LABEL_REGISTER).string(userId).field(signPubEnc).field(agreePubEnc).toBytes();
    }

    /** AUTH: resposta ao desafio aleatório que o relay envia no login. */
    public static byte[] msgAuth(String userId, byte[] challenge) {
        return new Bytes.Writer().field(LABEL_AUTH).string(userId).field(challenge).toBytes();
    }

    /**
     * CHALLENGE: o que o RELAY assina para provar ao cliente que é o relay verdadeiro.
     * O relay assina com RelayIdentity.sign(msgRelayChallenge(userId, nonce)); o cliente verifica com a
     * relay.pub que tem guardada. Inclui o userId e o nonce, por isso a assinatura não serve para outro
     * utilizador nem para outro login (não pode ser repetida).
     */
    public static byte[] msgRelayChallenge(String userId, byte[] nonce) {
        return new Bytes.Writer().field(LABEL_RELAY).string(userId).field(nonce).toBytes();
    }

    // ---------------- cliente: assinar ----------------

    public static byte[] signRegister(PrivateKey signKey, String userId, byte[] signPubEnc, byte[] agreePubEnc) {
        return sign(signKey, msgRegister(userId, signPubEnc, agreePubEnc));
    }

    public static byte[] signAuth(PrivateKey signKey, String userId, byte[] challenge) {
        return sign(signKey, msgAuth(userId, challenge));
    }

    // ---------------- relay: verificar ----------------

    /** Verifica o REGISTER usando a própria chave Ed25519 que vem no pedido. Nunca lança: devolve false. */
    public static boolean verifyRegister(String userId, byte[] signPubEnc, byte[] agreePubEnc, byte[] sig) {
        try {
            PublicKey pk = Keys.decodeSigningPublic(signPubEnc);
            Keys.decodeAgreementPublic(agreePubEnc); // a chave X25519 também tem de ser válida
            return verify(pk, msgRegister(userId, signPubEnc, agreePubEnc), sig);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    public static boolean verifyAuth(PublicKey signKey, String userId, byte[] challenge, byte[] sig) {
        return verify(signKey, msgAuth(userId, challenge), sig);
    }

    /** Cliente: confirma que o CHALLENGE foi assinado pelo relay cuja chave pública (relay.pub) conhece. */
    public static boolean verifyRelayChallenge(byte[] relayPubEnc, String userId, byte[] nonce, byte[] sig) {
        try {
            return verify(Keys.decodeSigningPublic(relayPubEnc), msgRelayChallenge(userId, nonce), sig);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    // ---------------- internos ----------------

    private static byte[] sign(PrivateKey k, byte[] data) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(k);
            s.update(data);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("falha ao assinar", e);
        }
    }

    private static boolean verify(PublicKey k, byte[] data, byte[] sig) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(k);
            s.update(data);
            return s.verify(sig);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }
}