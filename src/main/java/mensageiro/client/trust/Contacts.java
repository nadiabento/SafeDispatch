package mensageiro.client.trust;

import mensageiro.common.crypto.Bytes;
import mensageiro.common.crypto.Registration;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Chaves públicas já vistas de cada contacto ("trust on first use", como o SSH).
 *
 * O relay responde às pesquisas, por isso pode mentir. Defesa:
 *  - a primeira vez que vemos um utilizador, guardamos as chaves e mostramos a impressão digital
 *    para o utilizador comparar por outro canal (voz, pessoalmente);
 *  - nas vezes seguintes, se as chaves forem diferentes, recusamos.
 */
public final class Contacts {

    public enum Result { NEW, KNOWN, CHANGED }

    private final Map<String, Registration> byId = new ConcurrentHashMap<>();

    /** Regista (se novo) ou compara (se já conhecido). Em CHANGED não substitui o que estava guardado. */
    public Result pin(Registration r) {
        Registration old = byId.putIfAbsent(r.userId(), r);
        if (old == null) return Result.NEW;
        boolean same = Bytes.constantTimeEquals(old.signPub(), r.signPub())
                && Bytes.constantTimeEquals(old.agreePub(), r.agreePub());
        return same ? Result.KNOWN : Result.CHANGED;
    }
}
