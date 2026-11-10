# Documento de arquitetura — versão 1 (Entrega 1)

> Rascunho em Markdown para passar para o modelo fornecido pelo docente. Partes marcadas **[Nadia]** são do relay.

## 1. Componentes

```
 Cliente A                          Relay                          Cliente B
┌────────────────┐  TCP + frames  ┌───────────────────┐  TCP + frames  ┌────────────────┐
│ Cli            │◄──────────────►│ Servidor (pool)   │◄──────────────►│ Cli            │
│ ClientSession  │                │ Diretório         │                │ ClientSession  │
│ KeyVault       │                │ Autenticação      │                │ KeyVault       │
│ Contacts (TOFU)│                │ Encaminhamento    │                │ Contacts (TOFU)│
└────────────────┘                └───────────────────┘                └────────────────┘
        └──────────── envelope cifrado e assinado de ponta a ponta ──────────────┘
```
- **Cliente** (`client/`): `Cli` (comandos), `ClientSession` (registo, autenticação, pesquisa, envio, receção), `KeyVault` (cofre da chave privada), `Contacts` (chaves já vistas). É o único sítio com chaves privadas e texto em claro.
- **Relay** (`relay/`) **[Nadia]**: aceita ligações TCP num pool de threads de tamanho fixo, mantém o diretório de chaves públicas, autentica clientes e encaminha envelopes. Não é de confiança para o conteúdo. Tem uma identidade Ed25519 própria (`RelayIdentity`).
- **Comum** (`common/`): `crypto` (chaves, KDF, envelope, assinaturas, `Registration`) e `protocol` (frames e codec).

## 2. Elementos de segurança

| Objetivo | Mecanismo |
|---|---|
| Confidencialidade | Cifra híbrida: X25519 efémero + HKDF-SHA256 + AES-256-GCM |
| Integridade | GCM (tag) + assinatura Ed25519 sobre o envelope; cabeçalho como AAD |
| Autenticidade do remetente | Assinatura Ed25519 verificada antes de decifrar, contra a chave obtida do diretório |
| Prova de posse no registo | Assinatura sobre id + chaves públicas (`Proofs.msgRegister`) |
| Autenticação do cliente | Nonce aleatório de uso único assinado pelo cliente |
| Autenticação do relay | O relay assina o nonce; o cliente verifica com a `relay.pub` que já tem (impressão digital mostrada no arranque do relay) |
| Confiança nas chaves do diretório | Impressão digital + fixação à primeira utilização (`Contacts`): chaves diferentes depois → recusado |
| Chave privada em repouso | `KeyVault` (Módulo A) |
| Repetições | `msgId` aleatório; o cliente descarta `msgId` já visto |
| Entrada hostil | Comprimentos verificados antes de alocar; bytes a mais, truncados ou desconhecidos → recusados |

Decisões: só primitivas da JCA (Ed25519, X25519, AES-GCM, HMAC-SHA256, PBKDF2); HKDF escrito sobre HMAC (a JCA não o oferece), validado com os vetores da RFC 5869.

## 3. Formato das mensagens
Ver `docs/protocolo.md` (registo, autenticação, pesquisa, envio, entrega, erro, envelope).

## 4.1 Fluxo: Alice envia uma mensagem a Bob
1. Alice faz `register alice`: o cliente cria o cofre com a palavra-passe, envia `REGISTER` com a prova de posse e autentica-se (`AUTH_HELLO` → `CHALLENGE` → `AUTH`). No `CHALLENGE` verifica que o relay é o esperado. O Bob faz o mesmo.
2. Alice faz `send bob ...`: o cliente faz `LOOKUP bob`, verifica a prova de registo e fixa as chaves (mostra a impressão digital na primeira vez).
3. Alice cria o envelope (X25519 efémero + HKDF + AES-GCM + assinatura) e envia `SEND`.
4. O relay lê só o cabeçalho, confirma que o remetente é a Alice autenticada e entrega `DELIVER` ao Bob.
5. Bob lê o remetente do cabeçalho, faz `LOOKUP alice`, verifica a assinatura e só depois decifra. Descarta repetições.
Nas execuções seguintes basta `login alice` (abre o cofre).

## Módulo A — chave privada protegida
O `KeyVault` guarda a identidade (id e os dois pares de chaves) num ficheiro: `field(cabeçalho) field(nonce) field(cifra)`, com o cabeçalho `("SDKV", versão, iterações, sal de 16 bytes)`.
A chave AES-256 vem de **PBKDF2WithHmacSHA256** com sal aleatório e 600 000 iterações (valor recomendado pela OWASP para esta variante; o custo por tentativa é o que trava um ataque offline).
A cifra é AES-256-GCM e o cabeçalho entra como AAD, por isso qualquer byte alterado, no cabeçalho ou na cifra, é detetado ao abrir. Um tecto de iterações impede que um ficheiro malicioso bloqueie o cliente.
A escrita é atómica (ficheiro temporário + renomear). "Palavra-passe errada" e "ficheiro alterado" dão o mesmo erro, o que é inevitável com AEAD.
**Falta** (Entrega 2): atraso crescente após falhas consecutivas.
Limitação (questão A): quem copia o ficheiro ignora qualquer atraso da aplicação e testa palavras-passe offline; só o custo do PBKDF2, o sal e a qualidade da palavra-passe o travam. PBKDF2 não é resistente a memória (GPUs) e a JCA não tem scrypt/Argon2.

## Módulo B — anexos grandes por blocos (mecanismo escolhido; implementação na Entrega 2)
O ficheiro é lido e cifrado em fluxo, em blocos de 64 KiB, nunca inteiro em memória. Cada ficheiro tem uma chave AES-256 aleatória, enviada ao destinatário dentro de um `Envelope` normal (assinado). O nonce de cada bloco (12 bytes) é um prefixo aleatório de 4 bytes por ficheiro mais um contador de 8 bytes, por isso nunca se repete com a mesma chave. O AAD de cada bloco inclui o id do ficheiro, o índice do bloco e uma marca de "último bloco": blocos reordenados, removidos, alterados ou um ficheiro truncado falham a verificação.
O envio usa vários frames (limite de 1 MiB), com tipos de mensagem novos a acordar com o relay.
Limitação (questão B): só se sabe que o ficheiro está íntegro quando o último bloco é verificado; os blocos anteriores já foram entregues à aplicação e têm de ser tratados como provisórios até lá.

## Módulo C — credenciais temporárias **[Nadia]**
(Meia página com o mecanismo dos tokens: identidade, âmbito, expiração, renovação.)
