package mensageiro;

public final class SmokeTest {
    static void testJcaDisponivel() throws Exception {
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        java.security.KeyPairGenerator.getInstance("Ed25519");
    }
}
