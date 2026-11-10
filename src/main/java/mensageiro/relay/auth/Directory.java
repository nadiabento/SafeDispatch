package mensageiro.relay.auth;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Diretório de utilizadores do relay: nome -> chaves públicas.
 * Guardado em memória (a persistência em disco fica para a Entrega 2).
 * É seguro para várias threads (ConcurrentHashMap).
 */
public final class Directory {
    /** Nome válido: 3 a 32 caracteres, só letras minúsculas, dígitos e '_'. */
    private static final Pattern NOME_VALIDO = Pattern.compile("[a-z0-9_]{3,32}");

    /** Um utilizador registado: o nome, a chave de assinatura (Ed25519) e a de acordo de chave (X25519). */
    public record Entry(String user, byte[] pubSign, byte[] pubKex) {}

    private final ConcurrentHashMap<String, Entry> users = new ConcurrentHashMap<>();

    public static boolean nomeValido(String user) { return NOME_VALIDO.matcher(user).matches(); }

    /** As chaves têm de ser mesmo chaves Ed25519 / X25519 válidas, e não bytes quaisquer. */
    static boolean chavesValidas(byte[] pubSign, byte[] pubKex) {
        try {
            KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pubSign));
            KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(pubKex));
            return true;
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /**
     * Acrescenta o utilizador. Devolve false se o nome já existe.
     * putIfAbsent é atómico: dois registos simultâneos com o mesmo nome nunca passam os dois.
     */
    public boolean adicionar(Entry e) { return users.putIfAbsent(e.user(), e) == null; }

    /** Devolve o utilizador, ou null se não existir. */
    public Entry procurar(String user) { return users.get(user); }
}