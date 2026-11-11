package mensageiro.relay.store;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Armazenamento diferido: guarda mensagens para quem está offline.
 *
 * O relay só guarda ENVELOPES CIFRADOS (bytes opacos): nunca vê o conteúdo.
 *
 * Autorização: cada destinatário tem a sua fila e TODAS as operações (levantar, confirmar)
 * recebem o nome do utilizador AUTENTICADO na ligação. Por isso ninguém consegue ler nem
 * apagar mensagens de outra pessoa, mesmo conhecendo o msgId.
 *
 * Disponibilidade (defesa contra quem enche o servidor): há limites por destinatário
 * (número de mensagens e bytes) e as mensagens expiram ao fim de um tempo.
 *
 * Nota: está em memória. Se o relay reiniciar, as mensagens pendentes perdem-se.
 */
public final class MessageStore {

    /** Uma mensagem guardada. */
    public record Mensagem(String remetente, byte[] msgId, byte[] envelope, long guardadaEm) {}

    /** Valores por omissão. */
    public static final int MAX_MENSAGENS = 1000;
    public static final long MAX_BYTES = 16L * 1024 * 1024;       // 16 MiB por destinatário
    public static final long TTL_MS = 7L * 24 * 3600 * 1000;      // 7 dias

    private final int maxMensagens;
    private final long maxBytes;
    private final long ttlMs;
    private final LongSupplier relogio;                            // permite testar a expiração

    private final ConcurrentHashMap<String, Fila> filas = new ConcurrentHashMap<>();

    /** A fila de UM destinatário. Os métodos são synchronized: várias threads podem usá-la. */
    private static final class Fila {
        // LinkedHashMap mantém a ordem de chegada. A chave é o msgId em hexadecimal.
        final LinkedHashMap<String, Mensagem> msgs = new LinkedHashMap<>();
        long bytes = 0;

        void remover(String chave) {
            Mensagem m = msgs.remove(chave);
            if (m != null) bytes -= m.envelope().length;
        }
    }

    public MessageStore() { this(MAX_MENSAGENS, MAX_BYTES, TTL_MS, System::currentTimeMillis); }

    public MessageStore(int maxMensagens, long maxBytes, long ttlMs, LongSupplier relogio) {
        this.maxMensagens = maxMensagens;
        this.maxBytes = maxBytes;
        this.ttlMs = ttlMs;
        this.relogio = relogio;
    }

    private static String chave(byte[] msgId) { return HexFormat.of().formatHex(msgId); }

    /** Apaga as mensagens expiradas (chamar com a fila já bloqueada). */
    private void expirar(Fila f) {
        long agora = relogio.getAsLong();
        f.msgs.values().removeIf(m -> {
            boolean velha = agora - m.guardadaEm() > ttlMs;
            if (velha) f.bytes -= m.envelope().length;
            return velha;
        });
    }

    /**
     * Guarda uma mensagem para 'destinatario'. Devolve false se a fila dele está cheia
     * (demasiadas mensagens ou demasiados bytes) ou se o msgId já existe.
     */
    public boolean guardar(String destinatario, String remetente, byte[] msgId, byte[] envelope) {
        Fila f = filas.computeIfAbsent(destinatario, d -> new Fila());
        synchronized (f) {
            expirar(f);
            if (f.msgs.size() >= maxMensagens) return false;
            if (f.bytes + envelope.length > maxBytes) return false;
            String k = chave(msgId);
            if (f.msgs.containsKey(k)) return false;
            f.msgs.put(k, new Mensagem(remetente, msgId.clone(), envelope.clone(), relogio.getAsLong()));
            f.bytes += envelope.length;
            return true;
        }
    }

    /**
     * Devolve, por ordem de chegada, as mensagens pendentes de 'destinatario' sem as apagar
     * (só se apagam quando o cliente as confirma). Para quando a soma dos envelopes chega a
     * 'maxBytes' ou a 'maxQuantidade' mensagens; devolve sempre pelo menos uma se existir.
     */
    public List<Mensagem> levantar(String destinatario, int maxBytes, int maxQuantidade) {
        Fila f = filas.get(destinatario);
        List<Mensagem> r = new ArrayList<>();
        if (f == null) return r;
        synchronized (f) {
            expirar(f);
            long soma = 0;
            for (Mensagem m : f.msgs.values()) {
                if (r.size() >= maxQuantidade) break;
                if (!r.isEmpty() && soma + m.envelope().length > maxBytes) break;
                r.add(m);
                soma += m.envelope().length;
            }
        }
        return r;
    }

    /** Quantas mensagens pendentes tem este destinatário. */
    public int pendentes(String destinatario) {
        Fila f = filas.get(destinatario);
        if (f == null) return 0;
        synchronized (f) { expirar(f); return f.msgs.size(); }
    }

    /**
     * O destinatário confirma que recebeu estas mensagens e elas são apagadas.
     * Só apaga da fila DELE: um msgId de outra pessoa não faz nada.
     * Devolve quantas apagou.
     */
    public int confirmar(String destinatario, Collection<byte[]> msgIds) {
        Fila f = filas.get(destinatario);
        if (f == null) return 0;
        int n = 0;
        synchronized (f) {
            for (byte[] id : msgIds) {
                String k = chave(id);
                if (f.msgs.containsKey(k)) { f.remover(k); n++; }
            }
        }
        return n;
    }
}