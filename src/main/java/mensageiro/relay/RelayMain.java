package mensageiro.relay;

import mensageiro.relay.auth.RelayIdentity;
import mensageiro.relay.net.ClientHandler;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/*
 * Ponto de entrada do relay. Uso: RelayMain <porta>
 * Funcionamento:
 *   1. Carrega (ou cria) a identidade do relay.
 *   2. Abre a porta e fica à espera de clientes.
 *   3. Cada cliente que se liga é entregue a um ClientHandler, que corre numa thread do pool.
 * 
 * Porque um pool de tamanho fixo (disponibilidade): se criássemos uma thread nova por
 * ligação, um atacante podia abrir milhares de ligações e esgotar a memória do relay.
 * Com 64 threads no máximo, o relay aguenta, e os restantes ficam à espera.
 */
public final class RelayMain {
    static final int MAX_CLIENTES = 64;               // máximo de ligações tratadas ao mesmo tempo
    static final int TIMEOUT_INATIVIDADE_MS = 60_000; // 60 s sem receber nada -> fecha a ligação

    public static void main(String[] args) throws Exception {
        // Porta vem do 1.º argumento; se não houver, usa 5000
        int porta = args.length > 0 ? Integer.parseInt(args[0]) : 5000;

        // Identidade do relay (chaves em data/). O fingerprint serve para os clientes a confirmarem
        RelayIdentity identidade = RelayIdentity.loadOrCreate(Path.of("data"));
        System.out.println("Relay arrancou na porta " + porta);
        System.out.println("Fingerprint do relay: " + RelayIdentity.fingerprint(identidade.publicKeyBytes()));
        System.out.println("Chave pública para os clientes: data/relay.pub");

        ExecutorService pool = Executors.newFixedThreadPool(MAX_CLIENTES);

        // try-with-resources: o ServerSocket fecha sozinho se o programa terminar
        try (ServerSocket server = new ServerSocket(porta)) {
            while (true) {                                    // o relay corre até o parares (Ctrl+C)
                Socket socket = server.accept();              // bloqueia até chegar um cliente
                socket.setSoTimeout(TIMEOUT_INATIVIDADE_MS);  // leituras que demorem > 60 s dão timeout
                pool.submit(new ClientHandler(socket, identidade)); // entrega a uma thread do pool
            }
        }
    }
}