package mensageiro.common.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Derivação de chaves.
 *
 * Hoje: HKDF-SHA256 (RFC 5869), implementado sobre HmacSHA256 da JCA,
 * porque a JCA não traz HKDF pronto.
 * Dia 10/11 (Módulo A) acrescenta-se aqui o PBKDF2 para a palavra-passe.
 */
public final class Kdf {

    private Kdf() {}

    private static final String HMAC = "HmacSHA256";
    private static final int HASH_LEN = 32; // SHA-256

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            // HMAC com chave vazia não é aceite por SecretKeySpec; a RFC manda usar HASH_LEN zeros.
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[HASH_LEN] : key, HMAC));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 indisponível", e);
        }
    }

    /** HKDF-Extract: concentra a entropia do segredo partilhado numa chave pseudoaleatória (PRK). */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        return hmac(salt == null ? new byte[0] : salt, ikm);
    }

    /** HKDF-Expand: gera 'length' bytes a partir da PRK; 'info' separa usos diferentes da mesma PRK. */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        if (length < 0 || length > 255 * HASH_LEN) throw new IllegalArgumentException("length inválido");
        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        int pos = 0;
        for (int i = 1; pos < length; i++) {
            t = hmac(prk, Bytes.concat(t, info, new byte[]{(byte) i}));
            int n = Math.min(HASH_LEN, length - pos);
            System.arraycopy(t, 0, okm, pos, n);
            pos += n;
        }
        return okm;
    }

    /** Atalho: extract + expand numa só chamada. */
    public static byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length) {
        return hkdfExpand(hkdfExtract(salt, ikm), info, length);
    }

    // =====================================================================
    // PBKDF2 (Módulo A): chave derivada de uma palavra-passe
    // =====================================================================

    /**
     * PBKDF2WithHmacSHA256. O número de iterações é o que encarece cada tentativa
     * de um atacante que tenha copiado o ficheiro (ataque offline).
     */
    public static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyBytes) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBytes * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 indisponível", e);
        } finally {
            spec.clearPassword();
        }
    }
}