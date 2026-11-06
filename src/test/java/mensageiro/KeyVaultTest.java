package mensageiro;

import mensageiro.client.keystore.Identity;
import mensageiro.client.keystore.KeyVault;
import mensageiro.client.keystore.KeyVault.VaultException;
import mensageiro.common.crypto.Bytes;
import mensageiro.common.crypto.Envelope;
import mensageiro.common.crypto.Kdf;
import mensageiro.common.crypto.Keys;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static mensageiro.Asserts.*;

public final class KeyVaultTest {

    private static final int FAST = 1000; // iterações baixas só para testes que repetem muitas vezes

    private static Path tmp() throws Exception {
        Path d = Files.createTempDirectory("sdvault");
        d.toFile().deleteOnExit();
        return d.resolve("vault.bin");
    }

    private static boolean contains(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return true;
        }
        return false;
    }


    /** PBKDF2-SHA256: vetores conhecidos (1 e 2 iterações) */
    static void testPbkdf2Vetores() throws Exception {
        byte[] salt = Bytes.utf8("salt");
        assertEquals("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
                Bytes.toHex(Kdf.pbkdf2("password".toCharArray(), salt, 1, 32)), "1 iteração");
        assertEquals("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
                Bytes.toHex(Kdf.pbkdf2("password".toCharArray(), salt, 2, 32)), "2 iterações");
    }

    /** KeyVault: criar e abrir devolve a mesma identidade */
    static void testCriarEAbrirMesmaIdentidade() throws Exception {
        Path f = tmp();
        Identity a = KeyVault.create(f, "alice", "pw-correta".toCharArray(), FAST);
        Identity b = KeyVault.unlock(f, "pw-correta".toCharArray());
        assertEquals("alice", b.userId, "userId");
        assertArrayEquals(a.signPublicEncoded(), b.signPublicEncoded(), "chave de assinatura");
        assertArrayEquals(a.agreePublicEncoded(), b.agreePublicEncoded(), "chave de acordo");
        assertArrayEquals(Keys.encodePrivate(a.signKeys.getPrivate()),
                Keys.encodePrivate(b.signKeys.getPrivate()), "privada Ed25519");
        assertArrayEquals(Keys.encodePrivate(a.agreeKeys.getPrivate()),
                Keys.encodePrivate(b.agreeKeys.getPrivate()), "privada X25519");
    }

    /** KeyVault: identidade recuperada funciona (Envelope ponta a ponta) */
    static void testIdentidadeRecuperadaFuncionaComEnvelope() throws Exception {
        Path f = tmp();
        KeyVault.create(f, "alice", "pw".toCharArray(), FAST);
        Identity alice = KeyVault.unlock(f, "pw".toCharArray());
        Identity bob = Identity.generate("bob");
        byte[] env = Envelope.seal(Bytes.utf8("olá"), "alice", alice.signKeys.getPrivate(),
                "bob", bob.agreeKeys.getPublic());
        byte[] pt = Envelope.open(env, "alice", alice.signKeys.getPublic(), "bob", bob.agreeKeys).plaintext();
        assertArrayEquals(Bytes.utf8("olá"), pt, "mensagem");
    }

    /** KeyVault: palavra-passe errada é recusada */
    static void testPasswordErradaRecusada() throws Exception {
        Path f = tmp();
        KeyVault.create(f, "alice", "certa".toCharArray(), FAST);
        assertThrows(VaultException.class, () -> KeyVault.unlock(f, "errada".toCharArray()), "pw errada");
        assertThrows(VaultException.class, () -> KeyVault.unlock(f, new char[0]), "pw vazia");
    }

    /** KeyVault: o ficheiro sozinho não contém a chave privada em claro */
    static void testFicheiroSemChavePrivadaEmClaro() throws Exception {
        Path f = tmp();
        Identity id = KeyVault.create(f, "alice", "pw".toCharArray(), FAST);
        byte[] file = Files.readAllBytes(f);
        assertTrue(!contains(file, Keys.encodePrivate(id.signKeys.getPrivate())), "Ed25519 em claro");
        assertTrue(!contains(file, Keys.encodePrivate(id.agreeKeys.getPrivate())), "X25519 em claro");
        assertTrue(!contains(file, Bytes.utf8("alice")), "nem o userId em claro");
    }

    /** KeyVault: alterar QUALQUER byte do ficheiro é detetado */
    static void testAlterarQualquerByteDetetado() throws Exception {
        Path f = tmp();
        KeyVault.create(f, "alice", "pw".toCharArray(), FAST);
        byte[] orig = Files.readAllBytes(f);
        for (int i = 0; i < orig.length; i++) {
            byte[] t = orig.clone();
            t[i] ^= 0x01;
            Files.write(f, t);
            int pos = i;
            assertThrows(VaultException.class, () -> KeyVault.unlock(f, "pw".toCharArray()),
                    "byte " + pos + " alterado não foi detetado");
        }
    }

    /** KeyVault: ficheiro truncado, vazio ou lixo é recusado */
    static void testFicheiroTruncadoOuLixoRecusado() throws Exception {
        Path f = tmp();
        KeyVault.create(f, "alice", "pw".toCharArray(), FAST);
        byte[] orig = Files.readAllBytes(f);
        for (byte[] bad : new byte[][]{new byte[0], Arrays.copyOf(orig, orig.length / 2),
                Bytes.utf8("isto não é um cofre")}) {
            Files.write(f, bad);
            assertThrows(VaultException.class, () -> KeyVault.unlock(f, "pw".toCharArray()), "ficheiro inválido");
        }
    }

    /** KeyVault: create não sobrepõe um cofre existente */
    static void testCreateNaoSobrepoe() throws Exception {
        Path f = tmp();
        KeyVault.create(f, "alice", "pw".toCharArray(), FAST);
        assertThrows(VaultException.class, () -> KeyVault.create(f, "outra", "pw".toCharArray(), FAST),
                "sobrepor");
        assertEquals("alice", KeyVault.unlock(f, "pw".toCharArray()).userId, "o original mantém-se");
    }

    /** KeyVault: dois cofres com a mesma palavra-passe têm ficheiros diferentes (salt) */
    static void testSaltDiferenteFicheirosDiferentes() throws Exception {
        Path f1 = tmp(), f2 = tmp();
        KeyVault.create(f1, "a", "pw".toCharArray(), FAST);
        KeyVault.create(f2, "a", "pw".toCharArray(), FAST);
        assertTrue(!Arrays.equals(Files.readAllBytes(f1), Files.readAllBytes(f2)), "devem diferir");
    }

    /** KeyVault: iterações por omissão (600 000) demoram um tempo mensurável */
    static void testIteracoesPorOmissaoTempo() throws Exception {
        Path f = tmp();
        long t0 = System.nanoTime();
        KeyVault.create(f, "alice", "pw".toCharArray());
        long ms = (System.nanoTime() - t0) / 1_000_000;
        System.out.println("        (create com 600 000 iterações: " + ms + " ms)");
        assertEquals("alice", KeyVault.unlock(f, "pw".toCharArray()).userId, "abre");
    }
}