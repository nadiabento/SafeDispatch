package mensageiro.relay.net;

import mensageiro.common.protocol.*;
import mensageiro.relay.auth.Authenticator;
import mensageiro.relay.auth.Directory;

import java.io.*;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;

/*Trata UMA ligação de um cliente (corre numa thread do pool).
 * Lê frames em ciclo e trata cada tipo de mensagem.
 * Regras de segurança:
 *  - Frame ou campos inválidos (ProtocolException): envia ERROR e FECHA a ligação.
 *  - O remetente de uma mensagem é SEMPRE o utilizador autenticado nesta ligação
 *    (campo 'utilizador'), nunca algo que o cliente escreva.
 *  - O relay trata o envelope como bytes opacos: não o abre, não o altera.
 */
public final class ClientHandler implements Runnable {
    // Códigos de erro (1.º campo do payload de ERROR)
    static final int ERRO_PROTOCOLO = 1;
    static final int ERRO_NAO_IMPLEMENTADO = 2;
    static final int ERRO_PEDIDO_INVALIDO = 3;
    static final int ERRO_NAO_AUTENTICADO = 4;
    static final int ERRO_REGISTO_RECUSADO = 5;
    static final int ERRO_AUTENTICACAO = 6;
    static final int ERRO_DESTINATARIO = 7;

    // Tamanhos máximos dos campos (defesa contra campos forjados)
    static final int MAX_USER = 32;
    static final int MAX_CHAVE = 128;
    static final int MAX_ASSINATURA = 128;
    static final int MAX_ENVELOPE = 512 * 1024;
    static final int TAMANHO_NONCE = 32;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Socket socket;
    private final Authenticator authenticator;
    private final Sessions sessions;
    private OutputStream out;

    /* Utilizador autenticado nesta ligação (null até o handshake terminar com sucesso). */
    private String utilizador = null;
    /* Desafio pendente (null se não há). É de uso único. */
    private Authenticator.Desafio desafio = null;

    public ClientHandler(Socket socket, Authenticator authenticator, Sessions sessions) {
        this.socket = socket;
        this.authenticator = authenticator;
        this.sessions = sessions;
    }

    @Override
    public void run() {
        // Atenção: NÃO usar "try (socket)" aqui. Num try-with-resources o socket fecha ANTES de
        // correr o catch, e o ERROR que queremos enviar ao cliente perdia-se. Fechamos no finally.
        try {
            InputStream in = new BufferedInputStream(socket.getInputStream());
            out = socket.getOutputStream();
            while (true) {
                Frame.Message msg = Frame.read(in);
                if (msg == null) return;                      // o cliente fechou a ligação
                tratar(msg);
            }
        } catch (ProtocolException e) {
            tentarEnviarErro(ERRO_PROTOCOLO, e.getMessage()); // lixo no protocolo: avisa e fecha
        } catch (SocketTimeoutException e) {
            // ligação inativa: fecha em silêncio
        } catch (IOException e) {
            // ligação cortada
        } finally {
            if (utilizador != null) sessions.remover(utilizador, this);
            try { socket.close(); } catch (IOException ignorado) { }
        }
    }

    private void tratar(Frame.Message msg) throws IOException {
        switch (msg.type()) {
            case REGISTER -> registar(msg.payload());
            case AUTH_HELLO -> iniciarAutenticacao(msg.payload());
            case AUTH -> concluirAutenticacao(msg.payload());
            case LOOKUP -> procurar(msg.payload());
            case SEND -> enviar(msg.payload());
            default -> enviarErro(ERRO_NAO_IMPLEMENTADO, "não implementado: " + msg.type());
        }
    }

    //  REGISTER: nome, chaves e prova de posse
    private void registar(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        String user = r.string(MAX_USER);
        byte[] pubSign = r.bytes(MAX_CHAVE);
        byte[] pubKex = r.bytes(MAX_CHAVE);
        byte[] prova = r.bytes(MAX_ASSINATURA);
        r.end();

        byte[] cert = authenticator.registar(user, pubSign, pubKex, prova);
        if (cert == null) { enviarErro(ERRO_REGISTO_RECUSADO, "registo recusado"); return; }
        enviar(MessageType.REGISTER_OK, new Codec.Writer().bytes(cert).toByteArray());
    }

    //  Handshake, passo 1: AUTH_HELLO -> CHALLENGE 
    private void iniciarAutenticacao(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        String user = r.string(MAX_USER);
        byte[] nonceCliente = r.bytes(64);
        r.end();

        if (utilizador != null) { enviarErro(ERRO_PEDIDO_INVALIDO, "já autenticado"); return; }
        if (nonceCliente.length != TAMANHO_NONCE) { enviarErro(ERRO_PEDIDO_INVALIDO, "nonce inválido"); return; }

        Authenticator.Desafio d = authenticator.iniciar(user, nonceCliente);
        // Mesma mensagem para "utilizador desconhecido" e para "assinatura errada"
        if (d == null) { enviarErro(ERRO_AUTENTICACAO, "autenticação falhou"); return; }
        desafio = d;
        enviar(MessageType.CHALLENGE,
                new Codec.Writer().bytes(d.nonceRelay()).bytes(d.assinaturaRelay()).toByteArray());
    }

    // Handshake, passo 2: AUTH -> AUTH_OK 
    private void concluirAutenticacao(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        byte[] assinatura = r.bytes(MAX_ASSINATURA);
        r.end();

        Authenticator.Desafio d = desafio;
        desafio = null;                                        // uso único: gasto mesmo que falhe
        if (d == null) { enviarErro(ERRO_PROTOCOLO, "AUTH sem AUTH_HELLO"); return; }
        if (!authenticator.concluir(d, assinatura)) { enviarErro(ERRO_AUTENTICACAO, "autenticação falhou"); return; }

        utilizador = d.utilizador();
        sessions.registar(utilizador, this);
        // TODO módulo C: aqui vai o token. Por agora vai vazio, com expiração 0.
        enviar(MessageType.AUTH_OK, new Codec.Writer().bytes(new byte[0]).u64(0).toByteArray());
    }

    // LOOKUP: chaves públicas de outro utilizador (+ certificado do relay) 
    private void procurar(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        String user = r.string(MAX_USER);
        r.end();
        if (!exigirAutenticado()) return;

        Directory.Entry e = authenticator.directory().procurar(user);
        if (e == null) { enviarErro(ERRO_DESTINATARIO, "utilizador desconhecido"); return; }
        byte[] cert = authenticator.certificado(e.user(), e.pubSign(), e.pubKex());
        enviar(MessageType.LOOKUP_OK, new Codec.Writer()
                .string(e.user()).bytes(e.pubSign()).bytes(e.pubKex()).bytes(cert).toByteArray());
    }

    // SEND: encaminha o envelope para o destinatário, se estiver ligado
    private void enviar(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        String destinatario = r.string(MAX_USER);
        byte[] envelope = r.bytes(MAX_ENVELOPE);
        r.end();
        if (!exigirAutenticado()) return;

        ClientHandler alvo = sessions.obter(destinatario);
        if (alvo == null) {
            // TODO Entrega 2: guardar a mensagem (armazenamento diferido)
            enviarErro(ERRO_DESTINATARIO, "destinatário desconhecido ou offline");
            return;
        }
        byte[] msgId = new byte[16];
        RANDOM.nextBytes(msgId);
        try {
            alvo.entregar(utilizador, msgId, envelope);        // 'utilizador' = remetente autenticado
        } catch (IOException e) {
            enviarErro(ERRO_DESTINATARIO, "não foi possível entregar");
            return;
        }
        enviar(MessageType.SEND_OK, new Codec.Writer().bytes(msgId).toByteArray());
    }

    /* Chamado por OUTRA thread (a do remetente) para entregar uma mensagem a este cliente. */
    void entregar(String remetente, byte[] msgId, byte[] envelope) throws IOException {
        enviar(MessageType.DELIVER,
                new Codec.Writer().string(remetente).bytes(msgId).bytes(envelope).toByteArray());
    }

    private boolean exigirAutenticado() throws IOException {
        if (utilizador != null) return true;
        enviarErro(ERRO_NAO_AUTENTICADO, "autenticação necessária");
        return false;
    }

    /* Escritas sincronizadas: a thread do remetente e a desta ligação podem escrever ao mesmo tempo. */
    private void enviar(MessageType tipo, byte[] payload) throws IOException {
        synchronized (out) { Frame.write(out, tipo, payload); }
    }

    private void enviarErro(int codigo, String texto) throws IOException {
        enviar(MessageType.ERROR, new Codec.Writer().u8(codigo).string(texto).toByteArray());
    }

    private void tentarEnviarErro(int codigo, String texto) {
        try { if (out != null) enviarErro(codigo, texto); } catch (IOException ignorado) { }
    }
}