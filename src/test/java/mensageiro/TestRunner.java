package mensageiro;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/*
 * Mini executor de testes (só JDK, sem JUnit).
 
 * Dois estilos de teste são suportados:
 *  1) Estilo "registerAll": a classe de teste tem um método estático registerAll() que chama
 *     register("nome", () -> { ...asserts... }) para cada teste (usado em BytesKdfTest, EnvelopeTest).
 *  2) Estilo "testXxx": métodos estáticos cujo nome começa por "test" (SmokeTest, FrameTest...).
 
 * Para acrescentar uma classe de teste, põe-na numa das duas listas em main().
 */
public final class TestRunner {

    /** Corpo de um teste: pode lançar qualquer exceção (a cripto lança exceções verificadas). */
    @FunctionalInterface
    public interface Check { void run() throws Exception; }

    private record Case(String name, Check body) {}
    private static final List<Case> CASES = new ArrayList<>();

    /** Regista um teste com nome e corpo. */
    public static void register(String name, Check body) { CASES.add(new Case(name, body)); }

    // ---- Asserts (o último argumento é a mensagem mostrada se falhar) ----

    public static void assertTrue(boolean cond, String msg) {
        if (!cond) throw new AssertionError(msg);
    }
    public static void assertEquals(int esperado, int obtido, String msg) {
        if (esperado != obtido) throw new AssertionError(msg + ": esperado " + esperado + " mas foi " + obtido);
    }
    public static void assertEquals(long esperado, long obtido, String msg) {
        if (esperado != obtido) throw new AssertionError(msg + ": esperado " + esperado + " mas foi " + obtido);
    }
    public static void assertEquals(Object esperado, Object obtido, String msg) {
        if (!java.util.Objects.equals(esperado, obtido))
            throw new AssertionError(msg + ": esperado " + esperado + " mas foi " + obtido);
    }
    public static void assertArrayEquals(byte[] esperado, byte[] obtido, String msg) {
        if (!Arrays.equals(esperado, obtido)) throw new AssertionError(msg + ": os arrays são diferentes");
    }
    /** Exige que o corpo lance uma exceção do tipo indicado (ou subtipo). */
    public static void assertThrows(Class<? extends Throwable> tipo, Check corpo, String msg) {
        try {
            corpo.run();
        } catch (Throwable t) {
            if (tipo.isInstance(t)) return;
            throw new AssertionError(msg + ": esperava " + tipo.getSimpleName() + " mas veio " + t);
        }
        throw new AssertionError(msg + ": esperava " + tipo.getSimpleName() + " mas não houve exceção");
    }

    // ---- Estilo "testXxx": converte cada método test* numa entrada registada ----

    private static void registerTestMethods(Class<?> c) {
        for (Method m : c.getDeclaredMethods()) {
            if (!m.getName().startsWith("test")) continue;
            register(c.getSimpleName() + "." + m.getName(), () -> {
                try {
                    m.invoke(null);
                } catch (java.lang.reflect.InvocationTargetException e) {
                    Throwable causa = e.getCause();
                    if (causa instanceof Exception ex) throw ex;
                    throw (Error) causa;
                }
            });
        }
    }

    public static void main(String[] args) {
        // Estilo testXxx (testes da Jessica)
        for (Class<?> c : new Class<?>[]{BytesKdfTest.class, EnvelopeTest.class, ProofsTest.class,
                KeyVaultTest.class, ClientFlowTest.class}) {
            registerTestMethods(c);
        }

        // Estilo testXxx (testes da Nadia)
        for (Class<?> c : new Class<?>[]{SmokeTest.class, FrameTest.class, CodecTest.class, RelayIdentityTest.class}) {
            registerTestMethods(c);
        }

        int ok = 0, fail = 0;
        for (Case c : CASES) {
            try {
                c.body().run();
                ok++;
                System.out.println("OK    " + c.name());
            } catch (Throwable t) {
                fail++;
                System.out.println("FALHA " + c.name() + " -> " + t);
            }
        }
        System.out.printf("%d ok, %d falhas%n", ok, fail);
        if (fail > 0) System.exit(1);
    }
}