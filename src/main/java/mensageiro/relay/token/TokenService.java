package mensageiro.relay.token;

import mensageiro.common.protocol.Codec;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.function.LongSupplier;

/**
 * Módulo C: tokens de curta duração, emitidos depois da autenticação.
 *
 * Um token diz: "este utilizador, com este âmbito, esteve autenticado desde X e vale até Y".
 * É assinado com HMAC-SHA256 com uma chave que SÓ o relay conhece, por isso ninguém consegue
 * criar nem alterar um token sem o relay detetar.
 *
 * Formato (tudo codificado com o Codec, sem serialização Java):
 *   token   = bytes(payload) + bytes(mac)
 *   payload = u8 versão, string utilizador, u8 âmbito, u64 início, u64 expiração
 *   mac     = HMAC-SHA256( chave, contexto + payload )
 *
 * Limites ao dano de um token roubado:
 *  - expira em poucos minutos;
 *  - o âmbito só permite levantar as PRÓPRIAS mensagens;
 *  - a renovação tem um teto: passada a duração máxima da sessão é preciso autenticar outra vez.
 */
public final class TokenService {

    /** Âmbito: levantar (e confirmar) as próprias mensagens. */
    public static final int ESCOPO_LEVANTAR = 1;

    public static final long VALIDADE_MS = 5 * 60 * 1000;        // 5 minutos
    public static final long MAX_SESSAO_MS = 60 * 60 * 1000;     // 1 hora (teto das renovações)

    /** Tamanho máximo aceite para um token recebido (defesa contra campos forjados). */
    public static final int MAX_TOKEN = 256;

    private static final int VERSAO = 1;
    private static final int MAX_USER = 32;
    private static final int TAMANHO_MAC = 32;
    /** Texto fixo misturado no MAC: o MAC de um token nunca serve para outra coisa. */
    private static final byte[] CONTEXTO = "SafeDispatch/token/v1".getBytes(StandardCharsets.UTF_8);

    /** O token (bytes que vão para o cliente) e quando expira. */
    public record Token(byte[] bytes, long expiraEm) {}

    /** O que o token afirma, depois de verificado. */
    public record Dados(String utilizador, int escopo, long inicio, long expiraEm) {}

    private final byte[] chave;
    private final long validadeMs;
    private final long maxSessaoMs;
    private final LongSupplier relogio;          // permite testar a expiração sem esperar

    /** Chave aleatória nova (só existe em memória). */
    public TokenService() {
        this(novaChave(), VALIDADE_MS, MAX_SESSAO_MS, System::currentTimeMillis);
    }

    public TokenService(byte[] chave, long validadeMs, long maxSessaoMs, LongSupplier relogio) {
        this.chave = chave.clone();
        this.validadeMs = validadeMs;
        this.maxSessaoMs = maxSessaoMs;
        this.relogio = relogio;
    }

    private static byte[] novaChave() {
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        return k;
    }

    // ---------- emitir ----------

    /** Emite um token novo (chamado quando o utilizador acaba de se autenticar). */
    public Token emitir(String utilizador, int escopo) {
        long agora = relogio.getAsLong();
        return construir(utilizador, escopo, agora, agora + validadeMs);
    }

    private Token construir(String utilizador, int escopo, long inicio, long expiraEm) {
        byte[] payload = new Codec.Writer()
                .u8(VERSAO).string(utilizador).u8(escopo).u64(inicio).u64(expiraEm).toByteArray();
        byte[] token = new Codec.Writer().bytes(payload).bytes(mac(payload)).toByteArray();
        return new Token(token, expiraEm);
    }

    // ---------- verificar ----------

    /**
     * Verifica o token: MAC certo, não expirado e com o âmbito exigido.
     * Devolve os dados, ou null se for inválido por QUALQUER motivo. Nunca lança exceção.
     */
    public Dados verificar(byte[] token, int escopoExigido) {
        Dados d = abrir(token);
        if (d == null || d.escopo() != escopoExigido) return null;
        return d;
    }

    /** Verifica MAC e expiração (sem olhar ao âmbito). */
    private Dados abrir(byte[] token) {
        try {
            var r = new Codec.Reader(token);
            byte[] payload = r.bytes(MAX_TOKEN);
            byte[] macRecebido = r.bytes(TAMANHO_MAC);
            r.end();

            // Comparação em tempo constante (não revela quantos bytes coincidem)
            if (!MessageDigest.isEqual(mac(payload), macRecebido)) return null;

            var p = new Codec.Reader(payload);
            if (p.u8() != VERSAO) return null;
            String utilizador = p.string(MAX_USER);
            int escopo = p.u8();
            long inicio = p.u64();
            long expiraEm = p.u64();
            p.end();

            if (relogio.getAsLong() >= expiraEm) return null;      // expirado
            return new Dados(utilizador, escopo, inicio, expiraEm);
        } catch (Exception e) {
            return null;                                           // lixo, truncado, null...
        }
    }

    // ---------- renovar ----------

    /**
     * Troca um token ainda válido por outro com nova expiração. O início da sessão mantém-se,
     * e a expiração nunca passa de (início + duração máxima da sessão).
     * Devolve null se o token for inválido/expirado ou se a sessão já chegou ao teto.
     */
    public Token renovar(byte[] token) {
        Dados d = abrir(token);
        if (d == null) return null;
        long agora = relogio.getAsLong();
        long teto = d.inicio() + maxSessaoMs;
        if (agora >= teto) return null;                            // sessão demasiado longa
        long novaExpiracao = Math.min(agora + validadeMs, teto);
        return construir(d.utilizador(), d.escopo(), d.inicio(), novaExpiracao);
    }

    // ---------- MAC ----------

    private byte[] mac(byte[] payload) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(chave, "HmacSHA256"));
            m.update(CONTEXTO);
            return m.doFinal(payload);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC indisponível", e);
        }
    }
}