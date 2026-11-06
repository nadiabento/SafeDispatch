package mensageiro.common.protocol;

public enum MessageType {
    REGISTER(1), REGISTER_OK(2),
    AUTH_HELLO(3), CHALLENGE(4), AUTH(5), AUTH_OK(6),
    LOOKUP(7), LOOKUP_OK(8),
    SEND(9), SEND_OK(10),
    DELIVER(11),
    FETCH(12), FETCH_OK(13),
    RENEW(14), RENEW_OK(15),
    ERROR(255);

    public final int code;
    MessageType(int code) { this.code = code; }

    public static MessageType fromCode(int code) throws ProtocolException {
        for (MessageType t : values()) if (t.code == code) return t;
        throw new ProtocolException("tipo de mensagem desconhecido: " + code);
    }
}
