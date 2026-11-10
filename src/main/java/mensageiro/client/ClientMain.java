package mensageiro.client;

import mensageiro.client.ui.Cli;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Arranque do cliente. Uso: ClientMain <host> <porta> <relay.pub>
 * relay.pub é a chave pública do relay (data/relay.pub no relay): o cliente só confia num relay que a prove ter.
 * Confirme a impressão digital do relay (mostrada no arranque do relay) por um canal de confiança.
 */
public final class ClientMain {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("uso: ClientMain <host> <porta> <relay.pub>");
            System.exit(2);
        }
        int port;
        try {
            port = Integer.parseInt(args[1]);
        } catch (NumberFormatException e) {
            System.err.println("porta inválida: " + args[1]);
            System.exit(2);
            return;
        }
        byte[] relayPub;
        try {
            relayPub = Files.readAllBytes(Path.of(args[2]));
        } catch (java.io.IOException e) {
            System.err.println("não consegui ler a chave pública do relay em " + args[2]);
            System.exit(2);
            return;
        }
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        new Cli(in, System.out, args[0], port, relayPub, Path.of("data", "client"), true).run();
    }
}