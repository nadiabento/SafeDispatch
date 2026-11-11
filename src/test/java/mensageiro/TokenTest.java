package mensageiro;

import mensageiro.relay.token.TokenService;

import java.util.concurrent.atomic.AtomicLong;

/** Testes unitários do TokenService (sem rede; o relógio é simulado). */
public final class TokenTest {
    private static void check(boolean c, String m) { if (!c) throw new AssertionError(m); }
    private static final int ESC = TokenService.ESCOPO_LEVANTAR;

    // Um token recém-emitido verifica e diz quem é o dono
    static void testTokenValidoVerifica() {
        var s = new TokenService();
        var t = s.emitir("alice", ESC);
        var d = s.verificar(t.bytes(), ESC);
        check(d != null, "o token devia ser válido");
        check(d.utilizador().equals("alice"), "o dono devia ser a alice");
        check(d.expiraEm() == t.expiraEm(), "a expiração devia coincidir");
    }

    // Token expirado é recusado
    static void testTokenExpiradoRecusado() {
        var agora = new AtomicLong(1000);
        var s = new TokenService(new byte[32], 100, 10_000, agora::get);
        var t = s.emitir("alice", ESC);
        agora.set(1099);
        check(s.verificar(t.bytes(), ESC) != null, "ainda devia ser válido");
        agora.set(1100);
        check(s.verificar(t.bytes(), ESC) == null, "devia estar expirado");
    }

    // Token alterado (qualquer bit) é recusado
    static void testTokenAlteradoRecusado() {
        var s = new TokenService();
        byte[] original = s.emitir("alice", ESC).bytes();
        for (int i = 0; i < original.length; i++) {
            byte[] copia = original.clone();
            copia[i] ^= 1;
            check(s.verificar(copia, ESC) == null, "alterar o byte " + i + " devia invalidar o token");
        }
    }

    // Token emitido por outro serviço (outra chave) é recusado
    static void testTokenDeOutroServicoRecusado() {
        var a = new TokenService();
        var b = new TokenService();
        check(b.verificar(a.emitir("alice", ESC).bytes(), ESC) == null, "chave diferente devia recusar");
    }

    // Âmbito errado é recusado
    static void testEscopoErradoRecusado() {
        var s = new TokenService();
        check(s.verificar(s.emitir("alice", ESC).bytes(), 2) == null, "âmbito diferente devia recusar");
    }

    // Lixo nunca lança exceção: devolve null
    static void testLixoNaoLancaExcecao() {
        var s = new TokenService();
        check(s.verificar(new byte[0], ESC) == null, "vazio");
        check(s.verificar(null, ESC) == null, "null");
        byte[] lixo = new byte[100];
        new java.security.SecureRandom().nextBytes(lixo);
        check(s.verificar(lixo, ESC) == null, "bytes aleatórios");
    }

    // Renovar estende a expiração
    static void testRenovarEstendeExpiracao() {
        var agora = new AtomicLong(1000);
        var s = new TokenService(new byte[32], 100, 10_000, agora::get);
        var t = s.emitir("alice", ESC);                 // expira em 1100
        agora.set(1050);
        var novo = s.renovar(t.bytes());
        check(novo != null && novo.expiraEm() == 1150, "devia expirar em 1150");
        agora.set(1120);
        check(s.verificar(t.bytes(), ESC) == null, "o token antigo já expirou");
        check(s.verificar(novo.bytes(), ESC) != null, "o novo ainda vale");
    }

    // Não se renova um token expirado
    static void testRenovarTokenExpiradoRecusado() {
        var agora = new AtomicLong(1000);
        var s = new TokenService(new byte[32], 100, 10_000, agora::get);
        var t = s.emitir("alice", ESC);
        agora.set(1100);
        check(s.renovar(t.bytes()) == null, "token expirado não se renova");
    }

    // As renovações têm um teto: passada a sessão máxima é preciso autenticar outra vez
    static void testRenovarNaoPassaDoMaximoDaSessao() {
        var agora = new AtomicLong(0);
        var s = new TokenService(new byte[32], 400, 1000, agora::get);
        var t = s.emitir("alice", ESC);                 // expira em 400
        agora.set(300);
        t = s.renovar(t.bytes());                       // expira em 700
        agora.set(600);
        t = s.renovar(t.bytes());                       // 1000 (cortado no teto)
        check(t != null && t.expiraEm() == 1000, "devia ficar no teto de 1000");
        agora.set(999);
        t = s.renovar(t.bytes());
        check(t != null && t.expiraEm() <= 1000, "nunca passa do teto");
        agora.set(1000);
        check(s.renovar(t.bytes()) == null, "no teto já não renova");
    }

    // Um token renovado continua a ser do mesmo utilizador
    static void testRenovarMantemODono() {
        var s = new TokenService();
        var novo = s.renovar(s.emitir("alice", ESC).bytes());
        check(novo != null && s.verificar(novo.bytes(), ESC).utilizador().equals("alice"), "continua da alice");
    }
}