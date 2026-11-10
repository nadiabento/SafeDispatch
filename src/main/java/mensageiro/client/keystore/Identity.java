package mensageiro.client.keystore;

import mensageiro.common.crypto.Keys;
import mensageiro.common.crypto.Proofs;

import java.security.KeyPair;

/**
 * A identidade de um utilizador: o seu nome e os dois pares de chaves.
 * Vive em memória depois de desbloquear o KeyVault.
 */
public final class Identity {

    public final String userId;
    public final KeyPair signKeys;   // Ed25519: assinar
    public final KeyPair agreeKeys;  // X25519: receber mensagens cifradas

    public Identity(String userId, KeyPair signKeys, KeyPair agreeKeys) {
        this.userId = userId;
        this.signKeys = signKeys;
        this.agreeKeys = agreeKeys;
    }

    public static Identity generate(String userId) {
        return new Identity(userId, Keys.generateSigning(), Keys.generateAgreement());
    }

    public byte[] signPublicEncoded() { return Keys.encodePublic(signKeys.getPublic()); }

    public byte[] agreePublicEncoded() { return Keys.encodePublic(agreeKeys.getPublic()); }

    /** Assinatura do pedido REGISTER (prova de posse da chave privada). */
    public byte[] signRegister() {
        return Proofs.signRegister(signKeys.getPrivate(), userId, signPublicEncoded(), agreePublicEncoded());
    }

    /** Resposta ao desafio do relay no login. */
    public byte[] signAuth(byte[] challenge) {
        return Proofs.signAuth(signKeys.getPrivate(), userId, challenge);
    }
}