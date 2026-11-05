package mensageiro.common.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * Envelope E2E: cifra híbrida + assinatura.
 *
 * ENVIAR (seal):
 *   1. gera um par X25519 efémero (novo em cada mensagem);
 *   2. segredo = X25519(privada efémera, pública X25519 do destinatário);
 *   3. chave AES-256 = HKDF(segredo, contexto);
 *   4. cifra com AES-256-GCM; o cabeçalho (ids, timestamp, msgId, chave efémera) vai como AAD;
 *   5. assina tudo com a chave Ed25519 do remetente.
 *
 * RECEBER (open):
 *   verifica a assinatura ANTES de decifrar, confere remetente e destinatário,
 *   repete o acordo de chaves com a sua privada X25519 e decifra.
 *
 * Formato (tudo com Bytes.Writer, campos com prefixo de comprimento):
 *   envelope  = field(body) field(assinatura)
 *   body      = field(cabeçalho) field(nonce) field(cifra)
 *   cabeçalho = u8(versão) string(remetente) string(destinatário)
 *               lng(timestamp ms) field(msgId) field(pública X25519 efémera)
 *
 * O relay trata o envelope como bytes opacos: só precisa de ler remetente/destinatário
 * (peek) para encaminhar, e não consegue ler nem alterar o conteúdo sem ser detetado.
 */
public final class Envelope {

    private Envelope() {}

    public static final int VERSION = 1;
    private static final SecureRandom RNG = new SecureRandom();
    private static final byte[] INFO_LABEL = Bytes.utf8("SafeDispatch/v1/msg-key");
    private static final int GCM_TAG_BITS = 128;
    private static final int NONCE_LEN = 12;
    private static final int MSG_ID_LEN = 16;

    /** Qualquer envelope inválido (malformado, adulterado, assinatura errada, destinatário errado...). */
    public static final class InvalidEnvelopeException extends Exception {
        public InvalidEnvelopeException(String m) { super(m); }
    }

    /** Resultado de abrir um envelope válido. */
    public record Opened(String senderId, String recipientId, byte[] msgId, long timestamp, byte[] plaintext) {}

    /** Campos do cabeçalho lidos SEM verificar nada. Só para encaminhar ou procurar a chave do remetente. */
    public record Header(String senderId, String recipientId, long timestamp, byte[] msgId) {}

    // =====================================================================
    // ENVIAR
    // =====================================================================

    public static byte[] seal(byte[] plaintext,
                              String senderId, PrivateKey senderSignKey,
                              String recipientId, PublicKey recipientAgreeKey) throws GeneralSecurityException {

        KeyPair eph = Keys.generateAgreement();
        byte[] ephPub = Keys.encodePublic(eph.getPublic());
        byte[] msgId = randomBytes(MSG_ID_LEN);

        byte[] header = new Bytes.Writer()
                .u8(VERSION)
                .string(senderId)
                .string(recipientId)
                .lng(System.currentTimeMillis())
                .field(msgId)
                .field(ephPub)
                .toBytes();

        byte[] key = deriveKey(eph.getPrivate(), recipientAgreeKey,
                senderId, recipientId, ephPub, Keys.encodePublic(recipientAgreeKey));

        byte[] nonce = randomBytes(NONCE_LEN);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        c.updateAAD(header);
        byte[] ct = c.doFinal(plaintext);

        byte[] body = new Bytes.Writer().field(header).field(nonce).field(ct).toBytes();

        Signature s = Signature.getInstance("Ed25519");
        s.initSign(senderSignKey);
        s.update(body);
        byte[] sig = s.sign();

        return new Bytes.Writer().field(body).field(sig).toBytes();
    }

    // =====================================================================
    // RECEBER
    // =====================================================================

    /** Lê remetente/destinatário sem verificar nada. NUNCA confiar nestes valores até chamar open(). */
    public static Header peek(byte[] envelope) throws InvalidEnvelopeException {
        try {
            Bytes.Reader r = new Bytes.Reader(envelope);
            byte[] body = r.field();
            Bytes.Reader b = new Bytes.Reader(body);
            return parseHeader(b.field()).header;
        } catch (RuntimeException e) {
            throw new InvalidEnvelopeException("envelope malformado");
        }
    }

    public static Opened open(byte[] envelope,
                              String expectedSenderId, PublicKey senderSignKey,
                              String myId, KeyPair myAgreeKeys) throws InvalidEnvelopeException {
        try {
            // 1) estrutura externa
            Bytes.Reader r = new Bytes.Reader(envelope);
            byte[] body = r.field();
            byte[] sig = r.field();
            r.requireEnd();

            // 2) assinatura ANTES de qualquer outra coisa
            if (!verify(senderSignKey, body, sig)) {
                throw new InvalidEnvelopeException("assinatura inválida");
            }

            // 3) estrutura interna
            Bytes.Reader b = new Bytes.Reader(body);
            byte[] headerBytes = b.field();
            byte[] nonce = b.field();
            byte[] ct = b.field();
            b.requireEnd();
            Parsed p = parseHeader(headerBytes);

            if (p.version != VERSION) throw new InvalidEnvelopeException("versão não suportada");
            if (nonce.length != NONCE_LEN) throw new InvalidEnvelopeException("nonce inválido");

            // 4) é de quem esperamos e é para nós?
            if (!p.header.senderId().equals(expectedSenderId)) {
                throw new InvalidEnvelopeException("remetente inesperado");
            }
            if (!p.header.recipientId().equals(myId)) {
                throw new InvalidEnvelopeException("envelope não é para este destinatário");
            }

            // 5) decifrar
            PublicKey ephPubKey = Keys.decodeAgreementPublic(p.ephPub);
            byte[] key = deriveKey(myAgreeKeys.getPrivate(), ephPubKey,
                    p.header.senderId(), p.header.recipientId(),
                    p.ephPub, Keys.encodePublic(myAgreeKeys.getPublic()));

            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            c.updateAAD(headerBytes);
            byte[] pt = c.doFinal(ct);

            return new Opened(p.header.senderId(), p.header.recipientId(),
                    p.header.msgId(), p.header.timestamp(), pt);

        } catch (InvalidEnvelopeException e) {
            throw e;
        } catch (GeneralSecurityException | RuntimeException e) {
            // mensagem genérica de propósito: não dizemos a um atacante o que falhou
            throw new InvalidEnvelopeException("envelope inválido");
        }
    }

    // =====================================================================
    // internos
    // =====================================================================

    private static final class Parsed {
        int version; Header header; byte[] ephPub;
    }

    private static Parsed parseHeader(byte[] h) {
        Bytes.Reader r = new Bytes.Reader(h);
        Parsed p = new Parsed();
        p.version = r.u8();
        String sender = r.string();
        String recipient = r.string();
        long ts = r.lng();
        byte[] msgId = r.field();
        p.ephPub = r.field();
        r.requireEnd();
        p.header = new Header(sender, recipient, ts, msgId);
        return p;
    }

    private static boolean verify(PublicKey key, byte[] data, byte[] sig) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update(data);
            return s.verify(sig);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * segredo X25519 -> chave AES-256 via HKDF.
     * O contexto (info) liga a chave aos dois ids e às duas chaves públicas envolvidas.
     */
    private static byte[] deriveKey(PrivateKey myPriv, PublicKey theirPub,
                                    String senderId, String recipientId,
                                    byte[] ephPubEnc, byte[] recipientPubEnc) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(myPriv);
        ka.doPhase(theirPub, true);
        byte[] shared = ka.generateSecret();

        // segredo todo a zeros = chave pública de ordem pequena (ataque): rejeitar
        int acc = 0;
        for (byte x : shared) acc |= x;
        if (acc == 0) throw new GeneralSecurityException("chave pública inválida");

        byte[] info = new Bytes.Writer()
                .field(INFO_LABEL)
                .string(senderId)
                .string(recipientId)
                .field(ephPubEnc)
                .field(recipientPubEnc)
                .toBytes();
        return Kdf.hkdf(null, shared, info, 32);
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }
}