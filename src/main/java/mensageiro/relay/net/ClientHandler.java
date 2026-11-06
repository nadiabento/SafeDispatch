package mensageiro.relay.net;

import mensageiro.common.protocol.*;
import mensageiro.relay.auth.RelayIdentity;

import java.io.*;
import java.net.Socket;
import java.net.SocketTimeoutException;

/* Trata UMA ligação de um cliente. Corre numa thread do pool (por isso implementa Runnable).
 
 * Ciclo de vida:
 *   - lê um frame -> trata a mensagem -> lê o seguinte -> ... até o cliente sair ou haver erro.

 * Estado atual: esqueleto. Todas as mensagens respondem ERROR "não implementado".
 * Os comentários TODO em tratar() são o que vai ser preenchido a seguir.
 */
public final class ClientHandler implements Runnable {
    // Códigos de erro enviados ao cliente (1.º campo do payload de ERROR)
    static final int ERRO_PROTOCOLO = 1;
    static final int ERRO_NAO_IMPLEMENTADO = 2;

    private final Socket socket;           // a ligação com este cliente
    private final RelayIdentity identidade; // chaves do relay (para assinar o desafio)

    /* Quem está autenticado NESTA ligação. É null até o handshake terminar com sucesso.
     * Regra de segurança: o remetente das mensagens é SEMPRE este campo, nunca o que o
     * cliente escreve na mensagem. Assim ninguém consegue enviar em nome de outro.
     */
    private String utilizador = null;

    public ClientHandler(Socket socket, RelayIdentity identidade) {
        this.socket = socket;
        this.identidade = identidade;
    }

    @Override
    public void run() {
        // try (socket): o socket fecha sempre no fim, haja ou não erro
        try (socket) {
            InputStream in = new BufferedInputStream(socket.getInputStream());
            OutputStream out = socket.getOutputStream();

            while (true) {
                Frame.Message msg = Frame.read(in);   // espera por uma mensagem completa
                if (msg == null) return;              // null = o cliente fechou a ligação normalmente
                tratar(msg, out);
            }
        } catch (ProtocolException e) {
            // O cliente enviou um frame inválido (gigante, tipo desconhecido...).
            // Avisa e fecha: não vale a pena continuar a falar com quem envia lixo.
            tentarEnviarErro(ERRO_PROTOCOLO, e.getMessage());
        } catch (SocketTimeoutException e) {
            // Ficou 60 s sem enviar nada: fecha em silêncio (liberta a thread para outros)
        } catch (IOException e) {
            // A ligação cortou: não há nada a fazer
        }
    }

    /** Decide o que fazer conforme o tipo da mensagem recebida. */
    private void tratar(Frame.Message msg, OutputStream out) throws IOException {
        switch (msg.type()) {
            // TODO REGISTER    -> Authenticator: verificar prova de posse, guardar no Directory
            // TODO AUTH_HELLO  -> enviar CHALLENGE (nonce + assinatura do relay)
            // TODO AUTH        -> verificar assinatura do utilizador e preencher 'utilizador'
            // TODO LOOKUP      -> Directory
            // TODO SEND        -> usar 'utilizador' como remetente (NUNCA o que o cliente diz)

            // Por agora, tudo o resto responde com um erro
            default -> enviarErro(out, ERRO_NAO_IMPLEMENTADO, "não implementado: " + msg.type());
        }
    }

    /*Envia uma mensagem ERROR: [código (1 byte)] [texto].
     * synchronized: mais tarde, outra thread pode querer entregar uma mensagem a este
     * cliente ao mesmo tempo. O synchronized garante que dois frames não se misturam.
     */
    private void enviarErro(OutputStream out, int codigo, String texto) throws IOException {
        byte[] payload = new Codec.Writer().u8(codigo).string(texto).toByteArray();
        synchronized (out) { Frame.write(out, MessageType.ERROR, payload); }
    }

    /** Tenta enviar o erro, mas se a ligação já cortou, ignora (não há a quem avisar). */
    private void tentarEnviarErro(int codigo, String texto) {
        try { enviarErro(socket.getOutputStream(), codigo, texto); } catch (IOException ignorado) { }
    }
}