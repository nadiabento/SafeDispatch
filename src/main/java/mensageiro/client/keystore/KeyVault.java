package mensageiro.client.keystore;

import mensageiro.common.crypto.Bytes;
import mensageiro.common.crypto.Kdf;
import mensageiro.common.crypto.Keys;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Cofre da chave privada (Módulo A). A chave privada nunca fica em claro no disco.
 *
 * Ficheiro:
 *   field(cabeçalho) field(nonce) field(cifra)
 *   cabeçalho = field("SDKV") u8(versão) int(iterações PBKDF2) field(salt 16 bytes)
 *   cifra     = AES-256-GCM( userId, chaves privadas e públicas ), com o cabeçalho como AAD
 *
 * Chave AES = PBKDF2WithHmacSHA256(palavra-passe, salt, iterações).
 *
 * Consequências:
 *  - o ficheiro sozinho não revela as chaves: é preciso adivinhar a palavra-passe;
 *  - qualquer byte alterado (cabeçalho ou cifra) faz a decifra falhar (GCM);
 *  - "palavra-passe errada" e "ficheiro alterado" são indistinguíveis, o que é inevitável com AEAD.
 *
 * Ainda por fazer neste ficheiro (Módulo A): atraso crescente após tentativas falhadas.
 */
public final class KeyVault {

    private KeyVault() {}

    public static final int DEFAULT_ITERATIONS = 600_000; // OWASP 2023 para PBKDF2-HMAC-SHA256
    private static final int MAX_ITERATIONS = 10_000_000; // tecto para um ficheiro malicioso não nos bloquear
    private static final int VERSION = 1;
    private static final byte[] MAGIC = Bytes.utf8("SDKV");
    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final SecureRandom RNG = new SecureRandom();

    public static final class VaultException extends Exception {
        public VaultException(String m) { super(m); }
    }

    /** Cria o ficheiro com uma identidade nova. Falha se o ficheiro já existir. */
    public static Identity create(Path file, String userId, char[] password) throws IOException, VaultException {
        return create(file, userId, password, DEFAULT_ITERATIONS);
    }

    public static Identity create(Path file, String userId, char[] password, int iterations)
            throws IOException, VaultException {
        if (Files.exists(file)) throw new VaultException("já existe um cofre em " + file);
        Identity id = Identity.generate(userId);
        write(file, id, password, iterations);
        return id;
    }

    public static Identity unlock(Path file, char[] password) throws IOException, VaultException {
        byte[] data = Files.readAllBytes(file);
        byte[] key = null;
        try {
            Bytes.Reader r = new Bytes.Reader(data);
            byte[] header = r.field();
            byte[] nonce = r.field();
            byte[] ct = r.field();
            r.requireEnd();

            Bytes.Reader h = new Bytes.Reader(header);
            if (!Arrays.equals(MAGIC, h.field())) throw new VaultException("não é um cofre SafeDispatch");
            if (h.u8() != VERSION) throw new VaultException("versão do cofre não suportada");
            int iterations = h.integer();
            byte[] salt = h.field();
            h.requireEnd();
            if (iterations < 1 || iterations > MAX_ITERATIONS || salt.length != SALT_LEN
                    || nonce.length != NONCE_LEN) {
                throw new VaultException("cofre inválido");
            }

            key = Kdf.pbkdf2(password, salt, iterations, 32);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            c.updateAAD(header);
            byte[] plain = c.doFinal(ct);

            try {
                Bytes.Reader p = new Bytes.Reader(plain);
                String userId = p.string();
                byte[] signPriv = p.field(), signPub = p.field();
                byte[] agreePriv = p.field(), agreePub = p.field();
                p.requireEnd();
                KeyPair sign = new KeyPair(Keys.decodeSigningPublic(signPub), Keys.decodeSigningPrivate(signPriv));
                KeyPair agree = new KeyPair(Keys.decodeAgreementPublic(agreePub), Keys.decodeAgreementPrivate(agreePriv));
                return new Identity(userId, sign, agree);
            } finally {
                Arrays.fill(plain, (byte) 0);
            }
        } catch (VaultException e) {
            throw e;
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new VaultException("palavra-passe errada ou cofre alterado");
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    // ---------------------------------------------------------------------

    private static void write(Path file, Identity id, char[] password, int iterations)
            throws IOException, VaultException {
        try {
            byte[] salt = new byte[SALT_LEN]; RNG.nextBytes(salt);
            byte[] nonce = new byte[NONCE_LEN]; RNG.nextBytes(nonce);

            byte[] header = new Bytes.Writer()
                    .field(MAGIC).u8(VERSION).integer(iterations).field(salt).toBytes();

            byte[] plain = new Bytes.Writer()
                    .string(id.userId)
                    .field(Keys.encodePrivate(id.signKeys.getPrivate()))
                    .field(Keys.encodePublic(id.signKeys.getPublic()))
                    .field(Keys.encodePrivate(id.agreeKeys.getPrivate()))
                    .field(Keys.encodePublic(id.agreeKeys.getPublic()))
                    .toBytes();

            byte[] key = Kdf.pbkdf2(password, salt, iterations, 32);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            c.updateAAD(header);
            byte[] ct = c.doFinal(plain);
            Arrays.fill(key, (byte) 0);
            Arrays.fill(plain, (byte) 0);

            byte[] out = new Bytes.Writer().field(header).field(nonce).field(ct).toBytes();

            // escrita atómica: ficheiro temporário + rename, para nunca ficar um cofre a meio
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.write(tmp, out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE);
        } catch (GeneralSecurityException e) {
            throw new VaultException("falha a cifrar o cofre");
        }
    }
}