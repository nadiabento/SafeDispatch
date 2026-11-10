package mensageiro.client.ui;

import mensageiro.client.ClientSession;
import mensageiro.client.keystore.Identity;
import mensageiro.client.keystore.KeyVault;
import mensageiro.common.crypto.Registration;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

/** Interface de linha de comandos. Lê comandos e mostra resultados; a lógica está na ClientSession e no KeyVault. */
public final class Cli {

    private static final DateTimeFormatter HOUR = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());
    private static final int MIN_PASSWORD = 8;

    private final BufferedReader in;
    private final PrintStream out;
    private final String host;
    private final int port;
    private final byte[] relayPub;
    private final Path vaultDir;
    private final boolean hidePassword; // true: usa a consola real (sem eco). Nos testes é false: lê de 'in'.
    private ClientSession session;

    /** Para testes: as palavras-passe são lidas de 'in', nunca da consola real. */
    public Cli(BufferedReader in, PrintStream out, String host, int port, byte[] relayPub, Path vaultDir) {
        this(in, out, host, port, relayPub, vaultDir, false);
    }

    /** hidePassword = true no uso normal: a palavra-passe é pedida na consola, sem aparecer no ecrã. */
    public Cli(BufferedReader in, PrintStream out, String host, int port, byte[] relayPub, Path vaultDir,
               boolean hidePassword) {
        this.in = in;
        this.out = out;
        this.host = host;
        this.port = port;
        this.relayPub = relayPub;
        this.vaultDir = vaultDir;
        this.hidePassword = hidePassword;
    }

    private synchronized void say(String s) { out.println(s); }

    public void run() throws IOException {
        try {
            session = new ClientSession(host, port, relayPub,
                    m -> say("\n[" + HOUR.format(Instant.ofEpochMilli(m.timestamp())) + "] " + m.from() + ": " + m.text()),
                    w -> say("\n(aviso) " + w));
        } catch (IOException e) {
            say("Não consegui ligar a " + host + ":" + port + " (" + e.getMessage() + ")");
            return;
        }
        say("Ligado a " + host + ":" + port + ". Escreva 'help' para ver os comandos.");

        String line;
        while (prompt() && (line = in.readLine()) != null) {
            line = line.strip();
            if (line.isEmpty()) continue;
            String[] p = line.split("\\s+", 3);
            try {
                switch (p[0]) {
                    case "help" -> help();
                    case "register" -> { need(p, 2, "register <id>"); doRegister(p[1]); }
                    case "login" -> { need(p, 2, "login <id>"); doLogin(p[1]); }
                    case "lookup" -> {
                        need(p, 2, "lookup <id>");
                        var l = session.lookup(p[1]);
                        say(p[1] + (l.firstTime() ? " (primeira vez)" : "") + " — impressão digital: " + l.fingerprint());
                    }
                    case "send" -> {
                        need(p, 3, "send <id> <texto>");
                        var l = session.send(p[1], p[2]);
                        say("Enviada." + (l.firstTime()
                                ? " Primeira vez com '" + p[1] + "': confirme a impressão digital por outro canal: " + l.fingerprint()
                                : ""));
                    }
                    case "me" -> say("id: " + session.myId() + " — impressão digital: " + session.myFingerprint());
                    case "quit", "exit" -> { session.close(); return; }
                    default -> say("Comando desconhecido. Escreva 'help'.");
                }
            } catch (IllegalArgumentException | IllegalStateException e) {
                say("Erro: " + e.getMessage());
            } catch (KeyVault.VaultException e) {
                say("Cofre: " + e.getMessage());
            } catch (GeneralSecurityException e) {
                say("Segurança: " + e.getMessage());
            } catch (IOException e) {
                say("Erro de rede/relay: " + e.getMessage());
            }
        }
        session.close();
    }

    /** Cria o cofre com palavra-passe, regista-se no relay e autentica. Se o relay recusar, apaga o cofre. */
    private void doRegister(String id) throws IOException, GeneralSecurityException, KeyVault.VaultException {
        if (!Registration.validUserId(id)) throw new IllegalArgumentException("id inválido (1 a 32 letras, dígitos, '.', '_' ou '-')");
        Files.createDirectories(vaultDir);
        Path file = vaultFile(id);
        if (Files.exists(file)) throw new IllegalArgumentException("já existe um cofre para '" + id + "': use 'login " + id + "'");
        char[] pw = askPassword("Escolha uma palavra-passe (mín. " + MIN_PASSWORD + " caracteres): ");
        try {
            if (pw.length < MIN_PASSWORD) throw new IllegalArgumentException("palavra-passe demasiado curta");
            Identity identity = KeyVault.create(file, id, pw);
            try {
                session.register(identity);
            } catch (IOException | GeneralSecurityException | RuntimeException e) {
                Files.deleteIfExists(file); // o registo falhou: não deixar um cofre órfão
                throw e;
            }
            say("Registado e autenticado como '" + id + "'. Cofre guardado em " + file);
            say("A sua impressão digital: " + session.myFingerprint());
        } finally {
            Arrays.fill(pw, ' ');
        }
    }

    /** Abre o cofre existente e autentica no relay. */
    private void doLogin(String id) throws IOException, GeneralSecurityException, KeyVault.VaultException {
        if (!Registration.validUserId(id)) throw new IllegalArgumentException("id inválido");
        Path file = vaultFile(id);
        if (!Files.exists(file)) throw new IllegalArgumentException("não há cofre para '" + id + "': use 'register " + id + "'");
        char[] pw = askPassword("Palavra-passe: ");
        try {
            Identity identity;
            try {
                identity = KeyVault.unlock(file, pw);
            } catch (NoSuchFileException e) {
                throw new IllegalArgumentException("cofre não encontrado");
            }
            if (!identity.userId.equals(id)) throw new KeyVault.VaultException("o cofre pertence a outro utilizador");
            session.login(identity);
            say("Autenticado como '" + id + "'.");
            say("A sua impressão digital: " + session.myFingerprint());
        } finally {
            Arrays.fill(pw, ' ');
        }
    }

    private Path vaultFile(String id) { return vaultDir.resolve(id + ".vault"); }

    /** Lê a palavra-passe sem a mostrar, se houver consola; senão (ex.: terminal do IDE) lê normalmente. */
    private char[] askPassword(String prompt) throws IOException {
        Console c = hidePassword ? System.console() : null;
        if (c != null) return c.readPassword("%s", prompt);
        synchronized (this) { out.print(prompt + "(atenção: vai aparecer no ecrã) "); out.flush(); }
        String s = in.readLine();
        if (s == null) throw new IOException("sem entrada");
        return s.toCharArray();
    }

    private boolean prompt() {
        synchronized (this) { out.print("> "); out.flush(); }
        return true;
    }

    private static void need(String[] p, int n, String usage) {
        if (p.length < n) throw new IllegalArgumentException("uso: " + usage);
    }

    private void help() {
        say("""
                Comandos:
                  register <id>        criar cofre com palavra-passe, registar no relay e autenticar
                  login <id>           abrir o cofre e autenticar (já registado)
                  lookup <id>          pesquisar um utilizador e ver a impressão digital
                  send <id> <texto>    enviar uma mensagem cifrada de ponta a ponta
                  me                   ver o seu id e a sua impressão digital
                  help | quit""");
    }
}