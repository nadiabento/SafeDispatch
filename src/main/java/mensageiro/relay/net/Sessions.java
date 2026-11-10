package mensageiro.relay.net;

import java.util.concurrent.ConcurrentHashMap;

/** Utilizadores atualmente ligados e autenticados: nome -> ligação. Seguro para várias threads. */
public final class Sessions {
    private final ConcurrentHashMap<String, ClientHandler> online = new ConcurrentHashMap<>();

    /** Regista a ligação. Se o utilizador já tinha outra, esta substitui-a. */
    public void registar(String user, ClientHandler h) { online.put(user, h); }

    /** Remove só se a entrada ainda for ESTA ligação (uma ligação mais nova não é apagada). */
    public void remover(String user, ClientHandler h) { online.remove(user, h); }

    public ClientHandler obter(String user) { return online.get(user); }
}