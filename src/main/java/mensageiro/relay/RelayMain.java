package mensageiro.relay;

import mensageiro.relay.auth.RelayIdentity;

import java.nio.file.Path;

/**
 * Ponto de entrada do relay. Uso: RelayMain <porta>
 * Carrega (ou cria) a identidade do relay, arranca o servidor e fica a correr até Ctrl+C.
 */
public final class RelayMain {
    public static void main(String[] args) throws Exception {
        // Porta vem do 1.º argumento; se não houver, usa 5000
        int porta = args.length > 0 ? Integer.parseInt(args[0]) : 5000;

        // As chaves do relay ficam em data/ (que está no .gitignore)
        RelayIdentity identidade = RelayIdentity.loadOrCreate(Path.of("data"));

        // O RelayServer abre a porta e trata cada cliente numa thread do pool
        RelayServer servidor = new RelayServer(identidade);
        servidor.start(porta);

        System.out.println("Relay arrancou na porta " + porta);
        System.out.println("Fingerprint do relay: " + RelayIdentity.fingerprint(identidade.publicKeyBytes()));
        System.out.println("Chave pública para os clientes: data/relay.pub");

        // As threads do servidor são "daemon": sem isto o programa terminava logo
        Thread.currentThread().join();
    }
}