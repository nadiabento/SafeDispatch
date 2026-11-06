package mensageiro;

import mensageiro.relay.auth.RelayIdentity;
import java.nio.file.*;
import java.util.Arrays;

/**
 * Testes da identidade do relay. Cada teste usa uma pasta temporária nova, para não
 * mexer na data/ verdadeira.
 */
public final class RelayIdentityTest {
    /** Falha o teste com a mensagem m se a condição c for falsa. */
    private static void check(boolean c, String m) { if (!c) throw new AssertionError(m); }

    // Caso normal: o que o relay assina, verifica-se com a chave pública dele.
    static void testAssinaturaVerifica() throws Exception {
        var id = RelayIdentity.loadOrCreate(Files.createTempDirectory("relay"));
        byte[] dados = "desafio".getBytes();
        byte[] sig = id.sign(dados);
        check(RelayIdentity.verify(id.publicKeyBytes(), dados, sig), "assinatura válida devia verificar");
    }

    // Integridade: se alguém alterar os dados, a assinatura deixa de servir.
    static void testDadosAlteradosRecusados() throws Exception {
        var id = RelayIdentity.loadOrCreate(Files.createTempDirectory("relay"));
        byte[] sig = id.sign("desafio".getBytes());
        check(!RelayIdentity.verify(id.publicKeyBytes(), "outro".getBytes(), sig), "dados alterados");
    }

    // Autenticidade do servidor: um relay falso tem outras chaves, por isso a assinatura
    // dele não verifica com a chave pública do relay verdadeiro. É este o teste que
    // prova "o servidor é o servidor" (ameaça: relay falso / MITM).
    static void testRelayFalsoRecusado() throws Exception {
        var verdadeiro = RelayIdentity.loadOrCreate(Files.createTempDirectory("relay"));
        var falso = RelayIdentity.loadOrCreate(Files.createTempDirectory("relay"));
        byte[] sigFalsa = falso.sign("desafio".getBytes());
        check(!RelayIdentity.verify(verdadeiro.publicKeyBytes(), "desafio".getBytes(), sigFalsa), "relay falso aceite");
    }

    // Persistência: ao reiniciar o relay, a identidade é a mesma (não gera chaves novas),
    // senão os clientes deixavam de confiar nele a cada reinício.
    static void testChavesPersistem() throws Exception {
        Path dir = Files.createTempDirectory("relay");
        var a = RelayIdentity.loadOrCreate(dir);   // 1.ª vez: gera e guarda
        var b = RelayIdentity.loadOrCreate(dir);   // 2.ª vez: lê do disco
        check(Arrays.equals(a.publicKeyBytes(), b.publicKeyBytes()), "chave devia ser a mesma");
    }
}