package mensageiro;

import mensageiro.client.keystore.Identity;
import mensageiro.common.crypto.Bytes;
import mensageiro.common.crypto.Proofs;

import static mensageiro.Asserts.*;

public final class ProofsTest {


    /** Proofs: REGISTER válido é aceite */
    static void testRegisterValidoAceite() throws Exception {
        Identity a = Identity.generate("alice");
        assertTrue(Proofs.verifyRegister("alice", a.signPublicEncoded(), a.agreePublicEncoded(),
                a.signRegister()), "deve verificar");
    }

    /** Proofs: REGISTER com outro userId, outra chave X25519 ou lixo é recusado */
    static void testRegisterAdulteradoRecusado() throws Exception {
        Identity a = Identity.generate("alice"), m = Identity.generate("mallory");
        byte[] sig = a.signRegister();
        assertTrue(!Proofs.verifyRegister("bob", a.signPublicEncoded(), a.agreePublicEncoded(), sig),
                "userId trocado");
        assertTrue(!Proofs.verifyRegister("alice", a.signPublicEncoded(), m.agreePublicEncoded(), sig),
                "chave X25519 trocada");
        assertTrue(!Proofs.verifyRegister("alice", m.signPublicEncoded(), a.agreePublicEncoded(), sig),
                "chave Ed25519 trocada (registar a chave de outro)");
        assertTrue(!Proofs.verifyRegister("alice", new byte[]{1, 2, 3}, a.agreePublicEncoded(), sig),
                "chave lixo não lança exceção");
        assertTrue(!Proofs.verifyRegister("alice", a.signPublicEncoded(), a.agreePublicEncoded(), new byte[64]),
                "assinatura lixo");
    }

    /** Proofs: AUTH válido é aceite; desafio ou utilizador diferente é recusado */
    static void testAuthValidoEAdulterado() throws Exception {
        Identity a = Identity.generate("alice");
        byte[] ch = new byte[32]; new java.util.Random(7).nextBytes(ch);
        byte[] sig = a.signAuth(ch);
        assertTrue(Proofs.verifyAuth(a.signKeys.getPublic(), "alice", ch, sig), "válido");
        byte[] ch2 = ch.clone(); ch2[0] ^= 1;
        assertTrue(!Proofs.verifyAuth(a.signKeys.getPublic(), "alice", ch2, sig), "outro desafio");
        assertTrue(!Proofs.verifyAuth(a.signKeys.getPublic(), "bob", ch, sig), "outro utilizador");
        assertTrue(!Proofs.verifyAuth(Identity.generate("x").signKeys.getPublic(), "alice", ch, sig),
                "outra chave");
    }

    /** Proofs: assinatura de REGISTER não serve como AUTH (separação de domínios) */
    static void testRegisterNaoServeComoAuth() throws Exception {
        Identity a = Identity.generate("alice");
        // um relay malicioso tenta usar como "desafio" os bytes que o REGISTER assina
        byte[] fakeChallenge = Proofs.msgRegister("alice", a.signPublicEncoded(), a.agreePublicEncoded());
        assertTrue(!Proofs.verifyAuth(a.signKeys.getPublic(), "alice", fakeChallenge, a.signRegister()),
                "domínios separados");
    }
}