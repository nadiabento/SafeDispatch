package mensageiro.common.crypto;

import mensageiro.common.protocol.Codec;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * Mensagens que são ASSINADAS no registo e na autenticação, e as funções para assinar/verificar.
 *
 * É a classe partilhada entre cliente e relay: o que o cliente assina tem de ser EXATAMENTE
 * o que o relay verifica, por isso os dois usam estes mesmos construtores de mensagem.
 *
 * Cada mensagem começa por um "contexto" (texto fixo), para que uma assinatura feita para um
 * fim (ex.: autenticar) nunca possa ser reutilizada para outro (ex.: registar).
 * Os campos são codificados com prefixo de comprimento (Codec), sem ambiguidades:
 * ("ab","c") nunca dá os mesmos bytes que ("a","bc").
 */
public final class Proofs {
    private Proofs() {}

    /** Prova de posse no registo: o cliente assina o seu nome e as suas duas chaves públicas. */
    public static byte[] registerMsg(String user, byte[] pubSign, byte[] pubKex) {
        return new Codec.Writer().string("SD-REGISTER").string(user).bytes(pubSign).bytes(pubKex).toByteArray();
    }

    /** O cliente prova que é o utilizador: assina os dois nonces e o nome. */
    public static byte[] authMsg(byte[] nonceCliente, byte[] nonceRelay, String user) {
        return new Codec.Writer().string("SD-AUTH").bytes(nonceCliente).bytes(nonceRelay).string(user).toByteArray();
    }

    /** O relay prova que é o relay: assina os mesmos dois nonces e o nome do utilizador. */
    public static byte[] srvMsg(byte[] nonceCliente, byte[] nonceRelay, String user) {
        return new Codec.Writer().string("SD-SRV").bytes(nonceCliente).bytes(nonceRelay).string(user).toByteArray();
    }

    /** Certificado do relay: "este utilizador tem estas chaves". Assinado pelo relay. */
    public static byte[] certMsg(String user, byte[] pubSign, byte[] pubKex) {
        return new Codec.Writer().string("SD-CERT").string(user).bytes(pubSign).bytes(pubKex).toByteArray();
    }

    /** Assina com Ed25519. */
    public static byte[] sign(PrivateKey key, byte[] msg) throws GeneralSecurityException {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    /** Verifica uma assinatura Ed25519, dada a chave pública em formato X.509. Nunca lança: erro = false. */
    public static boolean verify(byte[] pubX509, byte[] msg, byte[] sig) {
        try {
            PublicKey pub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pubX509));
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(pub);
            s.update(msg);
            return s.verify(sig);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }
}