package mensageiro.relay.auth;

import java.io.IOException;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Identidade do relay: um par de chaves Ed25519 (assinaturas digitais).
 *
 * Ideia: duas chaves matematicamente ligadas.
 *   - Chave PRIVADA: fica só no relay. Serve para ASSINAR.
 *   - Chave PÚBLICA: qualquer um a pode ter. Serve para VERIFICAR assinaturas.
 *
 * Como prova que o servidor é o servidor: o cliente tem a chave pública do relay guardada
 * (relay.pub). Quando fala com o relay, este assina um desafio. Se a assinatura verifica
 * com a chave pública, só quem tem a chave privada a podia ter feito. Um relay falso não a tem.
 *
 * Ficheiros (pasta data/, no .gitignore, NUNCA fazer commit da chave privada):
 *   relay.key  chave privada, formato PKCS#8
 *   relay.pub  chave pública, formato X.509 -> é esta que se dá aos clientes
 */
public final class RelayIdentity {
    private final PrivateKey privateKey;   // só usada dentro desta classe, para assinar
    private final PublicKey publicKey;

    // Construtor privado: só se cria uma identidade através de loadOrCreate()
    private RelayIdentity(PrivateKey priv, PublicKey pub) {
        this.privateKey = priv;
        this.publicKey = pub;
    }

    /**
     * Devolve a identidade do relay. Se já há chaves na pasta, lê-as; senão, gera um par novo.
     * Assim o relay mantém a mesma identidade quando é reiniciado (os clientes continuam a confiar).
     */
    public static RelayIdentity loadOrCreate(Path dir) throws GeneralSecurityException, IOException {
        Files.createDirectories(dir);                       // cria a pasta data/ se não existir
        Path keyFile = dir.resolve("relay.key");
        Path pubFile = dir.resolve("relay.pub");
        KeyFactory kf = KeyFactory.getInstance("Ed25519");  // converte bytes <-> objetos de chave

        // Caso 1: já existem as duas chaves -> lê do disco
        if (Files.exists(keyFile) && Files.exists(pubFile)) {
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile)));
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(pubFile)));
            return new RelayIdentity(priv, pub);
        }

        // Caso 2: primeira vez -> gera um par novo e guarda-o
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Files.write(keyFile, kp.getPrivate().getEncoded());   // getEncoded() = bytes PKCS#8
        Files.write(pubFile, kp.getPublic().getEncoded());    // getEncoded() = bytes X.509
        return new RelayIdentity(kp.getPrivate(), kp.getPublic());
    }

    /** Assina dados com a chave privada. O resultado é a "prova" de que o relay os assinou. */
    public byte[] sign(byte[] data) throws GeneralSecurityException {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(privateKey);   // modo "assinar", com a chave privada
        s.update(data);           // diz o que se vai assinar
        return s.sign();          // produz a assinatura
    }

    /** Bytes da chave pública, para enviar a clientes ou guardar. */
    public byte[] publicKeyBytes() { return publicKey.getEncoded(); }

    /*Verifica uma assinatura usando só a chave PÚBLICA. É o que o cliente faz para confirmar
     * que está mesmo a falar com o relay. É static porque não precisa da chave privada.
     * Devolve true se a assinatura é válida; false em qualquer outro caso (incluindo erros).
     */
    public static boolean verify(byte[] publicKeyBytes, byte[] data, byte[] signature) {
        try {
            PublicKey pub = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(pub);    // modo "verificar", com a chave pública
            s.update(data);       // os dados que supostamente foram assinados
            return s.verify(signature);
        } catch (GeneralSecurityException e) {
            // Chave mal formada ou assinatura com formato inválido: tratamos como "não verifica"
            return false;
        }
    }

    /**
     * Impressão digital da chave pública: SHA-256 em hexadecimal (64 caracteres).
     * É um "resumo" curto e único da chave, fácil de comparar por outro canal
     * (por exemplo por telefone) para ter a certeza de que é a chave certa.
     */
    public static String fingerprint(byte[] publicKeyBytes) throws GeneralSecurityException {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(publicKeyBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b));   // cada byte -> 2 dígitos hex
        return sb.toString();
    }
}