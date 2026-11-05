package mensageiro.common.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Geração e (de)codificação de chaves.
 *
 * Cada utilizador tem DOIS pares de chaves, com funções diferentes:
 *  - Ed25519 (assinatura): prova quem escreveu a mensagem.
 *  - X25519 (acordo de chaves): permite a quem envia cifrar só para o destinatário.
 *
 * Chaves públicas viajam em X.509 (SubjectPublicKeyInfo) e privadas em PKCS#8,
 * que são os formatos que a JCA já sabe produzir e ler.
 */
public final class Keys {

    private Keys() {}

    public static KeyPair generateSigning() {
        return generate("Ed25519");
    }

    public static KeyPair generateAgreement() {
        return generate("X25519");
    }

    private static KeyPair generate(String alg) {
        try {
            return KeyPairGenerator.getInstance(alg).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(alg + " indisponível (precisa de Java 17+)", e);
        }
    }

    // ---- públicas (X.509) ----

    public static byte[] encodePublic(PublicKey k) {
        return k.getEncoded();
    }

    public static PublicKey decodeSigningPublic(byte[] enc) throws GeneralSecurityException {
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(enc));
    }

    public static PublicKey decodeAgreementPublic(byte[] enc) throws GeneralSecurityException {
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(enc));
    }

    // ---- privadas (PKCS#8): usadas pelo KeyVault ----

    public static byte[] encodePrivate(PrivateKey k) {
        return k.getEncoded();
    }

    public static PrivateKey decodeSigningPrivate(byte[] enc) throws GeneralSecurityException {
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(enc));
    }

    public static PrivateKey decodeAgreementPrivate(byte[] enc) throws GeneralSecurityException {
        return KeyFactory.getInstance("X25519").generatePrivate(new PKCS8EncodedKeySpec(enc));
    }
}