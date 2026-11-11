package mensageiro;

import mensageiro.relay.store.MessageStore;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/** Testes unitários do MessageStore (sem rede). */
public final class StoreTest {
    private static void check(boolean c, String m) { if (!c) throw new AssertionError(m); }
    private static byte[] id(int n) { byte[] b = new byte[16]; b[15] = (byte) n; return b; }
    private static byte[] env(int tamanho) { return new byte[tamanho]; }

    // Guardar e levantar: ordem de chegada, e levantar NÃO apaga
    static void testGuardarELevantarPorOrdem() {
        var s = new MessageStore();
        check(s.guardar("bob", "alice", id(1), env(10)), "guardar 1");
        check(s.guardar("bob", "carol", id(2), env(10)), "guardar 2");
        var l = s.levantar("bob", 1000, 10);
        check(l.size() == 2 && l.get(0).remetente().equals("alice") && l.get(1).remetente().equals("carol"), "ordem");
        check(s.pendentes("bob") == 2, "levantar não apaga");
    }

    // Confirmar apaga
    static void testConfirmarApaga() {
        var s = new MessageStore();
        s.guardar("bob", "alice", id(1), env(10));
        s.guardar("bob", "alice", id(2), env(10));
        check(s.confirmar("bob", List.of(id(1))) == 1, "apagou uma");
        var l = s.levantar("bob", 1000, 10);
        check(l.size() == 1 && l.get(0).msgId()[15] == 2, "ficou só a 2.ª");
    }

    // Autorização: outro utilizador não apaga nem vê as mensagens do bob
    static void testOutroUtilizadorNaoAcedeAsMensagensDoBob() {
        var s = new MessageStore();
        s.guardar("bob", "alice", id(1), env(10));
        check(s.confirmar("mallory", List.of(id(1))) == 0, "mallory não pode apagar");
        check(s.levantar("mallory", 1000, 10).isEmpty(), "mallory não vê nada");
        check(s.pendentes("bob") == 1, "a mensagem do bob continua lá");
    }

    // Limite de mensagens por destinatário
    static void testLimiteDeMensagens() {
        var s = new MessageStore(2, 1000, 1000, () -> 0);
        check(s.guardar("bob", "a", id(1), env(1)) && s.guardar("bob", "a", id(2), env(1)), "2 cabem");
        check(!s.guardar("bob", "a", id(3), env(1)), "a 3.ª devia ser recusada");
        check(s.guardar("carol", "a", id(3), env(1)), "outro destinatário não é afetado");
    }

    // Limite de bytes por destinatário
    static void testLimiteDeBytes() {
        var s = new MessageStore(100, 100, 1000, () -> 0);
        check(s.guardar("bob", "a", id(1), env(60)), "60 cabem");
        check(!s.guardar("bob", "a", id(2), env(60)), "mais 60 não cabem");
        s.confirmar("bob", List.of(id(1)));
        check(s.guardar("bob", "a", id(2), env(60)), "depois de apagar volta a caber");
    }

    // msgId repetido é recusado
    static void testMsgIdRepetidoRecusado() {
        var s = new MessageStore();
        check(s.guardar("bob", "a", id(1), env(1)), "1.ª");
        check(!s.guardar("bob", "a", id(1), env(1)), "mesmo msgId");
    }

    // Expiração
    static void testMensagensExpiram() {
        var agora = new AtomicLong(0);
        var s = new MessageStore(10, 1000, 100, agora::get);
        s.guardar("bob", "a", id(1), env(1));
        agora.set(50);
        check(s.pendentes("bob") == 1, "ainda não expirou");
        agora.set(101);
        check(s.pendentes("bob") == 0, "devia ter expirado");
    }

    // O lote respeita o limite de bytes, mas devolve sempre pelo menos uma
    static void testLoteRespeitaLimiteDeBytes() {
        var s = new MessageStore();
        s.guardar("bob", "a", id(1), env(60));
        s.guardar("bob", "a", id(2), env(60));
        check(s.levantar("bob", 100, 10).size() == 1, "só cabe uma");
        check(s.levantar("bob", 10, 10).size() == 1, "uma mensagem maior que o limite sai na mesma");
    }

    // Várias threads a guardar: nenhuma mensagem se perde
    static void testGuardarEmSimultaneo() throws Exception {
        var s = new MessageStore();
        var ts = new Thread[8];
        for (int t = 0; t < ts.length; t++) {
            final int base = t * 100;
            ts[t] = new Thread(() -> {
                for (int i = 0; i < 100; i++) {
                    byte[] b = new byte[16];
                    b[14] = (byte) (base / 100); b[15] = (byte) i;
                    s.guardar("bob", "a", b, env(1));
                }
            });
            ts[t].start();
        }
        for (var t : ts) t.join();
        check(s.pendentes("bob") == 800, "esperava 800 e há " + s.pendentes("bob"));
    }
}