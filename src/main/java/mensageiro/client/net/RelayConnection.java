package mensageiro.client.net;

import mensageiro.common.protocol.Codec;
import mensageiro.common.protocol.Frame;
import mensageiro.common.protocol.MessageType;
import mensageiro.common.protocol.ProtocolException;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Ligação TCP ao relay.
 *
 * Uma thread lê sempre do socket: as mensagens DELIVER (empurradas pelo relay a qualquer momento) vão
 * para o handler; tudo o resto são respostas a pedidos e vai para uma fila. Os pedidos são
 * serializados (um de cada vez), por isso a resposta seguinte é sempre a do pedido em curso.
 */
public final class RelayConnection implements Closeable {

    /** O relay respondeu com ERROR: [código u8][texto]. */
    public static final class RelayException extends IOException {
        public final int code;
        public RelayException(int code, String m) { super(m); this.code = code; }
    }

    private static final Frame.Message CLOSED = new Frame.Message(MessageType.ERROR, new byte[0]);
    private static final long TIMEOUT_MS = 10_000;

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final BlockingQueue<Frame.Message> responses = new LinkedBlockingQueue<>();
    private final Consumer<byte[]> onDeliver;
    private volatile boolean closed;

    public RelayConnection(String host, int port, Consumer<byte[]> onDeliver) throws IOException {
        this.socket = new Socket(host, port);
        this.socket.setTcpNoDelay(true);
        this.in = new BufferedInputStream(socket.getInputStream());
        this.out = socket.getOutputStream();
        this.onDeliver = onDeliver;
        Thread t = new Thread(this::readLoop, "relay-reader");
        t.setDaemon(true);
        t.start();
    }

    private void readLoop() {
        try {
            Frame.Message m;
            while ((m = Frame.read(in)) != null) {
                if (m.type() == MessageType.DELIVER) onDeliver.accept(m.payload());
                else responses.add(m);
            }
        } catch (IOException e) {
            // ligação caiu ou frame inválido: tratado em request()
        } finally {
            closed = true;
            responses.add(CLOSED);
        }
    }

    /** Envia um pedido e espera pela resposta. Se for ERROR, lança RelayException. */
    public synchronized Frame.Message request(MessageType type, byte[] payload, MessageType expected) throws IOException {
        if (closed) throw new IOException("ligação fechada");
        synchronized (out) { Frame.write(out, type, payload); }
        Frame.Message m;
        try {
            m = responses.poll(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrompido");
        }
        if (m == null) throw new IOException("o relay não respondeu a tempo");
        if (m == CLOSED) throw new IOException("o relay fechou a ligação");
        if (m.type() == MessageType.ERROR) throw parseError(m.payload());
        if (m.type() != expected) {
            throw new ProtocolException("resposta inesperada: " + m.type() + " (esperava " + expected + ")");
        }
        return m;
    }

    private static RelayException parseError(byte[] payload) {
        try {
            Codec.Reader r = new Codec.Reader(payload);
            int code = r.u8();
            String text = r.string(512);
            r.end();
            return new RelayException(code, text);
        } catch (IOException e) {
            return new RelayException(0, new String(payload, StandardCharsets.UTF_8));
        }
    }

    @Override
    public void close() {
        closed = true;
        try { socket.close(); } catch (IOException ignored) { }
    }
}
