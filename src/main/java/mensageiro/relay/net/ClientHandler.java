package mensageiro.relay.net;

import mensageiro.common.protocol.*;
import mensageiro.relay.auth.Authenticator;
import mensageiro.relay.auth.Directory;
import mensageiro.relay.store.MessageStore;
import mensageiro.relay.token.TokenService;

import java.io.*;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Trata UMA ligação de um cliente (corre numa thread do pool).
 * Lê frames em ciclo e trata cada tipo de mensagem.
 *
 * Regras de segurança:
 *  - Frame ou campos inválidos (ProtocolException): envia ERROR e FECHA a ligação.
 *  - O remetente de uma mensagem é SEMPRE o utilizador autenticado nesta ligação
 *    (campo 'utilizador'), nunca algo que o cliente escreva.
 *  - O relay trata o envelope como bytes opacos: não o abre, não o altera.
 *  - Levantar mensagens (FETCH) exige um token válido que pertença ao utilizador desta ligação.
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
    static final int ERRO_ARMAZEM_CHEIO = 8;
    static final int ERRO_TOKEN = 9;

    // Tamanhos máximos dos campos (defesa contra campos forjados)
    static final int MAX_USER = 32;
    static final int MAX_CHAVE = 128;
    static final int MAX_ASSINATURA = 128;
    static final int MAX_ENVELOPE = 512 * 1024;
    static final int MAX_CONFIRMACOES = 256;          // msgIds que um FETCH pode confirmar
    static final int TAMANHO_MSGID = 16;
    static final int MAX_BYTES_POR_FETCH = 900 * 1024; // abaixo do limite de 1 MiB por frame
    static final int MAX_MSGS_POR_FETCH = 100;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Socket socket;
    private final Authenticator authenticator;
    private final Sessions sessions;
    private final MessageStore store;
    private final TokenService tokens;
    private OutputStream out;

    /** Utilizador autenticado nesta ligação (null até o handshake terminar com sucesso). */
    private String utilizador = null;
    /** Desafio pendente (null se não há). É de uso único. */
    private Authenticator.Desafio desafio = null;

    public ClientHandler(Socket socket, Authenticator authenticator, Sessions sessions,
                         MessageStore store, TokenService tokens) {
        this.socket = socket;
        this.authenticator = authenticator;
        this.sessions = sessions;
        this.store = store;
        this.tokens = tokens;
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
            case FETCH -> levantar(msg.payload());
            case RENEW -> renovar(msg.payload());
            default -> enviarErro(ERRO_NAO_IMPLEMENTADO, "não implementado: " + msg.type());
        }
    }

    // ---------- REGISTER: nome, chaves e prova de posse ----------
    private void registar(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        String user = r.string(MAX_USER);
        byte[] pubSign = r.bytes(MAX_CHAVE);
        byte[] pubKex = r.bytes(MAX_CHAVE);
        byte[] prova = r.bytes(MAX_ASSINATURA);
        r.end();

        if (!authenticator.registar(user, pubSign, pubKex, prova)) {
            enviarErro(ERRO_REGISTO_RECUSADO, "registo recusado");
            return;
        }
        enviar(MessageType.REGISTER_OK, new byte[0]);
    }

    // ---------- Handshake, passo 1: AUTH_HELLO -> CHALLENGE ----------
    private void iniciarAutenticacao(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        String user = r.string(MAX_USER);
        r.end();

        if (utilizador != null) { enviarErro(ERRO_PEDIDO_INVALIDO, "já autenticado"); return; }

        Authenticator.Desafio d = authenticator.iniciar(user);
        // Mesma mensagem para "utilizador desconhecido" e para "assinatura errada"
        if (d == null) { enviarErro(ERRO_AUTENTICACAO, "autenticação falhou"); return; }
        desafio = d;
        enviar(MessageType.CHALLENGE,
                new Codec.Writer().bytes(d.nonce()).bytes(d.assinaturaRelay()).toByteArray());
    }

    // ---------- Handshake, passo 2: AUTH -> AUTH_OK (com o token) ----------
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
        // O token que o cliente vai apresentar nos pedidos seguintes (FETCH, RENEW)
        TokenService.Token t = tokens.emitir(utilizador, TokenService.ESCOPO_LEVANTAR);
        enviar(MessageType.AUTH_OK, new Codec.Writer().bytes(t.bytes()).u64(t.expiraEm()).toByteArray());
    }

    // ---------- LOOKUP: chaves públicas de outro utilizador ----------
    private void procurar(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        String user = r.string(MAX_USER);
        r.end();
        if (!exigirAutenticado()) return;

        Directory.Entry e = authenticator.directory().procurar(user);
        if (e == null) { enviarErro(ERRO_DESTINATARIO, "utilizador desconhecido"); return; }
        enviar(MessageType.LOOKUP_OK, new Codec.Writer()
                .string(e.user()).bytes(e.pubSign()).bytes(e.pubKex()).toByteArray());
    }

    // ---------- SEND: entrega já se o destinatário estiver ligado, senão guarda ----------
    private void enviar(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        String destinatario = r.string(MAX_USER);
        byte[] envelope = r.bytes(MAX_ENVELOPE);
        r.end();
        if (!exigirAutenticado()) return;

        // Só se aceitam mensagens para utilizadores registados
        if (authenticator.directory().procurar(destinatario) == null) {
            enviarErro(ERRO_DESTINATARIO, "destinatário desconhecido");
            return;
        }
        byte[] msgId = new byte[TAMANHO_MSGID];
        RANDOM.nextBytes(msgId);

        boolean entregue = false;
        ClientHandler alvo = sessions.obter(destinatario);
        if (alvo != null) {
            try {
                alvo.entregar(utilizador, msgId, envelope);    // 'utilizador' = remetente autenticado
                entregue = true;
            } catch (IOException e) {
                // a ligação do destinatário falhou: cai para o armazenamento
            }
        }
        if (!entregue && !store.guardar(destinatario, utilizador, msgId, envelope)) {
            enviarErro(ERRO_ARMAZEM_CHEIO, "a caixa do destinatário está cheia");
            return;
        }
        enviar(MessageType.SEND_OK, new Codec.Writer().bytes(msgId).toByteArray());
    }

    // ---------- FETCH: levanta as mensagens pendentes (exige token) ----------
    // Payload: bytes token, u32 n, n x bytes(msgId)  (os msgIds recebidos antes, a apagar)
    // Resposta FETCH_OK: u8 maisPendentes, u32 n, n x (string remetente, bytes msgId, bytes envelope)
    private void levantar(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        byte[] token = r.bytes(TokenService.MAX_TOKEN);
        long n = r.u32();
        if (n > MAX_CONFIRMACOES) throw new ProtocolException("confirmações a mais: " + n);
        List<byte[]> ids = new ArrayList<>();
        for (long i = 0; i < n; i++) {
            byte[] id = r.bytes(TAMANHO_MSGID);
            if (id.length != TAMANHO_MSGID) throw new ProtocolException("msgId inválido");
            ids.add(id);
        }
        r.end();
        if (!exigirAutenticado()) return;
        if (!tokenValido(token)) { enviarErro(ERRO_TOKEN, "token inválido ou expirado"); return; }

        // Só apaga da fila do utilizador AUTENTICADO (nunca de outra pessoa)
        store.confirmar(utilizador, ids);

        List<MessageStore.Mensagem> lote = store.levantar(utilizador, MAX_BYTES_POR_FETCH, MAX_MSGS_POR_FETCH);
        var w = new Codec.Writer();
        w.u8(store.pendentes(utilizador) > lote.size() ? 1 : 0);
        w.u32(lote.size());
        for (var m : lote) w.string(m.remetente()).bytes(m.msgId()).bytes(m.envelope());
        enviar(MessageType.FETCH_OK, w.toByteArray());
    }

    // ---------- RENEW: troca um token válido por outro com nova expiração ----------
    // Payload: bytes token.  Resposta RENEW_OK: bytes token, u64 expiração
    private void renovar(byte[] payload) throws IOException {
        var r = new Codec.Reader(payload);
        byte[] token = r.bytes(TokenService.MAX_TOKEN);
        r.end();
        if (!exigirAutenticado()) return;
        if (!tokenValido(token)) { enviarErro(ERRO_TOKEN, "token inválido ou expirado"); return; }

        TokenService.Token novo = tokens.renovar(token);
        if (novo == null) { enviarErro(ERRO_TOKEN, "sessão demasiado longa: autentica de novo"); return; }
        enviar(MessageType.RENEW_OK, new Codec.Writer().bytes(novo.bytes()).u64(novo.expiraEm()).toByteArray());
    }

    /** O token é válido, tem o âmbito certo e PERTENCE ao utilizador autenticado nesta ligação. */
    private boolean tokenValido(byte[] token) {
        TokenService.Dados d = tokens.verificar(token, TokenService.ESCOPO_LEVANTAR);
        return d != null && d.utilizador().equals(utilizador);
    }

    /** Chamado por OUTRA thread (a do remetente) para entregar uma mensagem a este cliente. */
    void entregar(String remetente, byte[] msgId, byte[] envelope) throws IOException {
        enviar(MessageType.DELIVER,
                new Codec.Writer().string(remetente).bytes(msgId).bytes(envelope).toByteArray());
    }

    private boolean exigirAutenticado() throws IOException {
        if (utilizador != null) return true;
        enviarErro(ERRO_NAO_AUTENTICADO, "autenticação necessária");
        return false;
    }

    /** Escritas sincronizadas: a thread do remetente e a desta ligação podem escrever ao mesmo tempo. */
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