package mensageiro;

import java.util.List;

public final class TestRunner {
    public static void main(String[] args) throws Exception {
        List<Class<?>> classes = List.of(SmokeTest.class, FrameTest.class, CodecTest.class);
        int ok = 0, fail = 0;
        for (Class<?> c : classes) {
            for (var m : c.getDeclaredMethods()) {
                if (!m.getName().startsWith("test")) continue;
                try {
                    m.invoke(null);
                    ok++;
                    System.out.println("OK    " + c.getSimpleName() + "." + m.getName());
                } catch (Throwable e) {
                    fail++;
                    System.out.println("FALHA " + c.getSimpleName() + "." + m.getName() + " -> " + e.getCause());
                }
            }
        }
        System.out.printf("%d ok, %d falhas%n", ok, fail);
        if (fail > 0) System.exit(1);
    }
}
