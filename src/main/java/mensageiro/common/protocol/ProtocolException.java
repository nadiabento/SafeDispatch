package mensageiro.common.protocol;

import java.io.IOException;

public final class ProtocolException extends IOException {
    public ProtocolException(String msg) { super(msg); }
}
