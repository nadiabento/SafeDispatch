package mensageiro;

import java.util.Arrays;

/** Funções de verificação para os testes do cliente/criptografia (não depende do TestRunner). */
public final class Asserts {
    private Asserts() {}

    public interface Code { void run() throws Exception; }

    public static void assertTrue(boolean c, String msg) {
        if (!c) throw new AssertionError(msg);
    }

    public static void assertEquals(Object exp, Object act, String msg) {
        if (exp == null ? act != null : !exp.equals(act))
            throw new AssertionError(msg + " (esperado=" + exp + ", obtido=" + act + ")");
    }

    public static void assertArrayEquals(byte[] exp, byte[] act, String msg) {
        if (!Arrays.equals(exp, act)) throw new AssertionError(msg);
    }

    /** Verifica que o código lança uma exceção do tipo indicado. */
    public static void assertThrows(Class<? extends Throwable> type, Code c, String msg) {
        try {
            c.run();
        } catch (Throwable e) {
            if (type.isInstance(e)) return;
            throw new AssertionError(msg + " (lançou " + e.getClass().getSimpleName() + ")");
        }
        throw new AssertionError(msg + " (não lançou nada)");
    }
}