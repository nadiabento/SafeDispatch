package mensageiro;

import java.util.ArrayList;
import java.util.List;

/**
 * Mini framework de testes (o enunciado só permite bibliotecas do JDK, logo sem JUnit).
 * Uso: Suite.register("nome", () -> { ... assertTrue(...) ... });
 */
public final class TestRunner {

    public interface Test { void run() throws Exception; }

    private static final List<String> names = new ArrayList<>();
    private static final List<Test> tests = new ArrayList<>();

    public static void register(String name, Test t) { names.add(name); tests.add(t); }

    // ----- asserts -----
    public static void assertTrue(boolean c, String msg) { if (!c) throw new AssertionError(msg); }
    public static void assertEquals(Object exp, Object act, String msg) {
        if (exp == null ? act != null : !exp.equals(act))
            throw new AssertionError(msg + " (esperado=" + exp + ", obtido=" + act + ")");
    }
    public static void assertArrayEquals(byte[] exp, byte[] act, String msg) {
        if (!java.util.Arrays.equals(exp, act)) throw new AssertionError(msg);
    }
    /** Verifica que o código lança uma exceção do tipo indicado. */
    public static void assertThrows(Class<? extends Throwable> type, Test t, String msg) {
        try { t.run(); }
        catch (Throwable e) {
            if (type.isInstance(e)) return;
            throw new AssertionError(msg + " (lançou " + e.getClass().getSimpleName() + ")");
        }
        throw new AssertionError(msg + " (não lançou nada)");
    }

    public static void main(String[] args) {
        // Cada ficheiro de testes regista-se aqui. Acrescentar novas suites nesta lista.
        BytesKdfTest.registerAll();
        EnvelopeTest.registerAll();

        int ok = 0, fail = 0;
        for (int i = 0; i < tests.size(); i++) {
            try {
                tests.get(i).run();
                System.out.println("  OK    " + names.get(i));
                ok++;
            } catch (Throwable e) {
                System.out.println("  FALHA " + names.get(i) + " -> " + e);
                fail++;
            }
        }
        System.out.println("\n" + ok + " ok, " + fail + " falhas");
        System.exit(fail == 0 ? 0 : 1);
    }
}