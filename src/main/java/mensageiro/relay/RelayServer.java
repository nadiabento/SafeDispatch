package mensageiro.relay;

import mensageiro.relay.auth.Authenticator;
import mensageiro.relay.auth.Directory;
import mensageiro.relay.auth.RelayIdentity;
import mensageiro.relay.net.ClientHandler;
import mensageiro.relay.net.Sessions;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* O servidor: aceita ligações e entrega cada uma a um ClientHandler num pool de threads.
 * Está separado do RelayMain para os testes poderem arrancar um relay real numa porta livre.
 
 * Disponibilidade: o pool tem tamanho FIXO e as ligações inativas expiram.
 */
public final class RelayServer implements AutoCloseable {
    static final int MAX_CLIENTES = 64;
    static final int TIMEOUT_INATIVIDADE_MS = 60_000;

    private final Authenticator authenticator;
    private final Sessions sessions = new Sessions();
    private final ExecutorService pool = Executors.newFixedThreadPool(MAX_CLIENTES, r -> {
        Thread t = new Thread(r, "relay-cliente");
        t.setDaemon(true);
        return t;
    });
    private ServerSocket server;

    public RelayServer(RelayIdentity identidade) {
        this.authenticator = new Authenticator(new Directory(), identidade);
    }

    /** Abre a porta (0 = qualquer porta livre) e começa a aceitar. Devolve a porta usada. */
    public int start(int porta) throws IOException {
        server = new ServerSocket(porta);
        Thread aceitar = new Thread(this::aceitar, "relay-aceitar");
        aceitar.setDaemon(true);
        aceitar.start();
        return server.getLocalPort();
    }

    private void aceitar() {
        try {
            while (true) {
                Socket socket = server.accept();                 // espera por um cliente
                socket.setSoTimeout(TIMEOUT_INATIVIDADE_MS);     // 60 s parado -> fecha
                pool.submit(new ClientHandler(socket, authenticator, sessions));
            }
        } catch (IOException e) {
            // o ServerSocket foi fechado: fim normal
        }
    }

    @Override
    public void close() throws IOException {
        if (server != null) server.close();
        pool.shutdownNow();
    }
}