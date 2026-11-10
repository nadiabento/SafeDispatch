# Protocolo (versão 1 — Entrega 1)

> Formato proposto pela pessoa 1 (cliente e criptografia). Os pontos marcados **[Nadia]** têm de ser confirmados com o relay.

## Enquadramento (frame)
Cada mensagem TCP é `[4 bytes comprimento N][1 byte tipo][N-1 bytes payload]`, big-endian; `N` inclui o byte de tipo.
Limite `N <= 1 MiB`. Comprimento 0, acima do limite ou tipo desconhecido → ligação recusada, sem alocar memória primeiro.

## Campos do payload
Os payloads usam o `Codec`: `string`/`bytes` = `[4 bytes comprimento][dados]`, com tamanho máximo verificado antes de ler.
O leitor chama `end()` no fim: bytes a mais são recusados.

## Mensagens da Entrega 1

| Tipo | Sentido | Payload |
|---|---|---|
| `REGISTER` | C→R | `string(id) bytes(signPub) bytes(agreePub) bytes(prova de posse)` (classe `Registration`) |
| `REGISTER_OK` | R→C | vazio |
| `AUTH_HELLO` | C→R | `string(id)` |
| `CHALLENGE` | R→C | `bytes(nonce) bytes(assinatura do relay)`; nonce de 32 bytes aleatórios, novo em cada `AUTH_HELLO`, uso único |
| `AUTH` | C→R | `bytes(assinatura do cliente sobre o nonce)` |
| `AUTH_OK` | R→C | token opaco (formato do Módulo C; o cliente guarda-o sem o interpretar) |
| `LOOKUP` | C→R | `string(id)` |
| `LOOKUP_OK` | R→C | igual ao payload de `REGISTER` (a entrada do diretório tal como foi registada) |
| `SEND` | C→R | envelope E2E (bytes crus) |
| `SEND_OK` | R→C | vazio |
| `DELIVER` | R→C | envelope E2E, empurrado ao destinatário |
| `ERROR` | R→C | `u8(código) string(texto)` (como já está no `ClientHandler`) |

`id`: 1 a 32 caracteres de `[A-Za-z0-9_.-]`. `signPub`: Ed25519 (X.509). `agreePub`: X25519 (X.509).

## Assinaturas (código em `common/crypto/Proofs`, igual para cliente e relay)
Cada assinatura é Ed25519 sobre bytes com etiqueta própria, construídos pelas mesmas funções nos dois lados:
- **Registo** — `msgRegister(id, signPub, agreePub)`, etiqueta `SafeDispatch/register/v1`. Prova de posse da chave privada e liga a chave X25519 à identidade.
- **Autenticação do cliente** — `msgAuth(id, nonce)`, etiqueta `SafeDispatch/auth/v1`.
- **Autenticação do relay** — `msgRelayChallenge(id, nonce)`, etiqueta `SafeDispatch/relay-challenge/v1`. O relay assina com `RelayIdentity.sign(...)`; o cliente verifica com a `relay.pub` que já tem. Assim o cliente sabe que fala com o relay verdadeiro antes de responder.
As etiquetas diferentes impedem usar uma assinatura de um contexto noutro.

## Envelope E2E (código em `common/crypto/Envelope`)
`field(corpo) field(assinatura)`. O corpo tem versão, id do remetente, id do destinatário, timestamp, `msgId` aleatório, chave efémera X25519, nonce e texto cifrado.
- Chave de sessão = HKDF-SHA256(segredo X25519 efémero↔destinatário, contexto com ids e chaves públicas).
- Cifra AES-256-GCM, com o cabeçalho como dados autenticados (AAD).
- O remetente assina com Ed25519; o destinatário verifica **antes** de decifrar.
- O relay só lê o cabeçalho (`Envelope.peek`) para saber a quem entregar; não consegue ler nem alterar o conteúdo.

## O que o relay tem de fazer **[Nadia]**
1. `REGISTER`: `Registration.decode(payload)` e `reg.valid()`; guardar no diretório; recusar ids repetidos.
2. `AUTH_HELLO`: gerar nonce (32 bytes), responder `CHALLENGE` com `identidade.sign(Proofs.msgRelayChallenge(id, nonce))`.
3. `AUTH`: `Proofs.verifyAuth(chave do registo, id, nonce, assinatura)`; invalidar o nonce; preencher `utilizador` na ligação.
4. `LOOKUP`: devolver a entrada (`Registration.encode()`). Só para clientes autenticados.
5. `SEND`: o remetente do envelope tem de ser o `utilizador` autenticado; entregar com `DELIVER`.
O `FakeRelay` em `src/test` é uma implementação mínima destes passos e serve de referência.
