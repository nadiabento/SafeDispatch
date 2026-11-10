# Protocolo do Mensageiro Seguro (SafeDispatch)

Versão da Entrega 2 (rascunho). Descreve o que o relay implementa e o que o cliente tem de enviar.

## 1. Transporte e framing

- Sockets TCP, sem TLS. A segurança é feita pela nossa camada (assinaturas Ed25519 e envelopes E2E).
- Cada mensagem é um frame: comprimento (uint32) | tipo (uint8) | payload.
- Tamanho máximo de um frame: 1 MiB. O comprimento é verificado ANTES de reservar memória,
  por isso um frame com tamanho forjado (ex.: 2 GB) é recusado sem consumir memória.
- Sem serialização Java: os campos do payload são codificados à mão (classe Codec).

### Campos do payload (Codec)

| Tipo         | Codificação                                              |
| ------------ | -------------------------------------------------------- |
| u8, u32, u64 | inteiros de tamanho fixo                                 |
| bytes        | comprimento (u32) + conteúdo; cada leitura tem um máximo |
| string       | bytes em UTF-8, com o mesmo prefixo e máximo             |

- Cada campo é lido com um tamanho máximo (defesa contra campos forjados).
- No fim de cada mensagem, `end()` recusa bytes a mais.

## 2. Mensagens

| Tipo        | Sentido | Payload                                                    |
| ----------- | ------- | ---------------------------------------------------------- |
| REGISTER    | C -> R  | string user, bytes pubSign, bytes pubKex, bytes prova      |
| REGISTER_OK | R -> C  | vazio                                                      |
| AUTH_HELLO  | C -> R  | string user                                                |
| CHALLENGE   | R -> C  | bytes nonce, bytes assinaturaRelay                         |
| AUTH        | C -> R  | bytes assinaturaCliente                                    |
| AUTH_OK     | R -> C  | bytes token (vazio por agora), u64 expiração (0 por agora) |
| LOOKUP      | C -> R  | string user                                                |
| LOOKUP_OK   | R -> C  | string user, bytes pubSign, bytes pubKex                   |
| SEND        | C -> R  | string destinatário, bytes envelope                        |
| SEND_OK     | R -> C  | bytes msgId (16 bytes)                                     |
| DELIVER     | R -> C  | string remetente, bytes msgId, bytes envelope              |
| ERROR       | R -> C  | u8 código, string texto                                    |

### Códigos de erro

| Código | Significado                                                        |
| ------ | ------------------------------------------------------------------ |
| 1      | erro de protocolo (frame ou campos inválidos); a ligação é fechada |
| 2      | mensagem não implementada                                          |
| 3      | pedido inválido (ex.: já autenticado)                              |
| 4      | autenticação necessária                                            |
| 5      | registo recusado                                                   |
| 6      | autenticação falhou                                                |
| 7      | destinatário desconhecido ou offline                               |

## 3. Registo

1. O cliente gera um par Ed25519 (assinatura) e um par X25519 (acordo de chaves).
2. Envia REGISTER com o nome, as duas chaves públicas e a prova de posse:
   `prova = Proofs.signRegister(chavePrivadaEd25519, user, pubSign, pubKex)`.
3. O relay verifica a prova com a própria chave pública recebida (prova que o cliente
   tem a chave privada) e valida as duas chaves.
4. O nome tem de cumprir `[a-z0-9_]{3,32}` e não pode estar já registado.
5. Resposta: REGISTER_OK, ou ERROR 5 (mesma resposta para qualquer motivo de recusa).

## 4. Autenticação mútua (por ligação)

```
C -> R  AUTH_HELLO(user)
R -> C  CHALLENGE(nonce, Assina_relay(msgRelayChallenge(user, nonce)))
C -> R  AUTH(Assina_user(msgAuth(user, nonce)))
R -> C  AUTH_OK  (ou ERROR 6)
```

- O relay prova quem é: o cliente verifica a assinatura do relay com a `relay.pub` que
  tem guardada (a chave pública do relay, confirmada fora do canal pela impressão digital SHA-256).
  Um relay falso não tem a chave privada e é detetado.
- O cliente prova quem é: o relay verifica a resposta com a chave pública registada.
- O nonce tem 32 bytes aleatórios, é novo em cada ligação e de uso único.
  O desafio expira em 30 segundos.
- Uma resposta antiga (replay) não serve numa ligação nova, porque o nonce é diferente.
- Utilizador desconhecido e assinatura errada recebem a mesma resposta (ERROR 6),
  para não revelar quais nomes existem.
- As assinaturas têm um rótulo próprio para cada fim (registo, autenticação, desafio do relay),
  por isso uma assinatura de um tipo nunca é válida para outro.

## 5. Descoberta e envio

- LOOKUP e SEND só são aceites depois de autenticar (senão ERROR 4).
- O remetente indicado no DELIVER é SEMPRE o utilizador autenticado na ligação, nunca um
  valor escrito pelo cliente.
- O envelope é opaco para o relay: não o abre nem o altera. A confidencialidade, a integridade
  e a autenticidade da mensagem vêm do envelope E2E (cifra AES-256-GCM e assinatura do remetente),
  tratado pelo cliente.
- Se o destinatário não estiver ligado, o relay responde ERROR 7.
  O armazenamento diferido é da Entrega 2 (MessageStore).

## 6. O que NÃO está protegido (limitações conhecidas)

1. Nonce só do relay: a assinatura do relay não prova ao cliente que o desafio é recente.
   Um relay falso que tivesse gravado um desafio antigo poderia repeti-lo. Melhoria possível:
   o cliente também enviar um nonce no AUTH_HELLO e o relay assiná-lo.
2. Sem canal cifrado entre cliente e relay: um atacante ativo que reencaminhe todas as
   mensagens (MITM) não está coberto pelo handshake. O conteúdo das mensagens continua
   protegido pelo envelope E2E.
3. Sem certificados: a confiança nas chaves públicas dos outros utilizadores depende da
   verificação da impressão digital (fingerprint) fora do canal.
4. Disponibilidade: ligações inativas ocupam uma thread do pool (64) até ao timeout de 60 s.
5. A chave privada do relay (`data/`) fica em claro no disco; quem tiver acesso à máquina
   do relay pode fazer-se passar por ele.
