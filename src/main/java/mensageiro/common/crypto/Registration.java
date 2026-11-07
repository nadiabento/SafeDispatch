package mensageiro.common.crypto;

import mensageiro.common.protocol.Codec;
import mensageiro.common.protocol.ProtocolException;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.regex.Pattern;

/**
 * Entrada de um utilizador: o que vai no payload de REGISTER e de LOOKUP_OK.
 *   string(id) bytes(signPub) bytes(agreePub) bytes(prova de posse)
 * A prova é a assinatura Ed25519 de Proofs.msgRegister(...). Quem recebe (relay ou outro cliente)
 * pode verificá-la sozinho: não precisa de confiar em quem lha entregou.
 */
public record Registration(String userId, byte[] signPub, byte[] agreePub, byte[] sig) {

    public static final int MAX_ID = 32;
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9_.-]{1,32}");

    public static boolean validUserId(String id) {
        return id != null && ID.matcher(id).matches();
    }

    public byte[] encode() {
        return new Codec.Writer().string(userId).bytes(signPub).bytes(agreePub).bytes(sig).toByteArray();
    }

    public static Registration decode(byte[] payload) throws ProtocolException {
        Codec.Reader r = new Codec.Reader(payload);
        String id = r.string(MAX_ID);
        byte[] sp = r.bytes(256);
        byte[] ap = r.bytes(256);
        byte[] sg = r.bytes(256);
        r.end();
        return new Registration(id, sp, ap, sg);
    }

    /** Id válido + chaves bem formadas + prova de posse correta. */
    public boolean valid() {
        return validUserId(userId) && Proofs.verifyRegister(userId, signPub, agreePub, sig);
    }

    /** Impressão digital das duas chaves públicas, em grupos de 4 hex (128 bits), para comparar por outro canal. */
    public String fingerprint() {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256")
                    .digest(new Bytes.Writer().field(signPub).field(agreePub).toBytes());
            String hex = Bytes.toHex(h).substring(0, 32);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 4) {
                if (i > 0) sb.append(' ');
                sb.append(hex, i, i + 4);
            }
            return sb.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 indisponível", e);
        }
    }
}
