# SafeDispatch — Mensageiro Seguro (Grupo 5)

Sistema de mensagens seguras para uma empresa de logística (centro de despacho e motoristas em viagem), desenvolvido em Java para a disciplina de Segurança Informática.

Compõe-se de:

- **Cliente**: regista-se, descobre outros utilizadores e troca mensagens cifradas de ponta a ponta.
- **Relay**: servidor que encaminha e guarda mensagens, sem nunca ter acesso ao conteúdo em claro.

Restrições do projeto: só bibliotecas do JDK (JCA), sockets TCP (`java.net.Socket`/`ServerSocket`), protocolo de mensagens próprio, sem TLS e sem serialização nativa de Java.

## Módulos específicos do grupo

| Módulo | Tema                                                                                    |
| ------ | --------------------------------------------------------------------------------------- |
| A      | Proteção da chave privada no cliente (PBKDF2, atraso crescente, deteção de adulteração) |
| B      | Anexos grandes cifrados por blocos (AEAD, nonce por contador, processamento em fluxo)   |
| C      | Credenciais temporárias (tokens com identidade, âmbito e expiração, com renovação)      |

## Equipa

| Elemento | Responsabilidade                                                    |
| -------- | ------------------------------------------------------------------- |
| Nadia    | Relay e protocolo (`relay/`, `common/protocol/`), módulo C          |
| Jessica  | Cliente e criptografia (`client/`, `common/crypto/`), módulos A e B |

Detalhes em `docs/DIVISAO.md`.

## Requisitos

- **JDK 17 ou superior** (testado com Temurin 21).
- Em Windows: **Git Bash** (incluído no Git para Windows) para correr os scripts `.sh`.
- Sem dependências externas.

Confirma a instalação:

```bash
javac -version
```

Em Windows, se o Git Bash não encontrar o `javac`, acrescenta a pasta `bin` do JDK ao PATH (ajusta o caminho à tua versão):

```bash
export PATH="/c/Program Files/Eclipse Adoptium/jdk-21.0.13.9-hotspot/bin:$PATH"
```

## Compilar e testar

```bash
./scripts/build.sh     # compila para out/
./scripts/test.sh      # compila e corre todos os testes
```

Resultado esperado: todos os testes com `OK` e `N ok, 0 falhas` no fim.

## Executar

> TODO: confirmar os argumentos finais quando o relay e o cliente estiverem implementados.

1. Arrancar o relay (porta 5000):

   ```bash
   ./scripts/run-relay.sh 5000
   ```

2. Noutro terminal, arrancar um cliente:

   ```bash
   ./scripts/run-client.sh localhost 5000
   ```

3. Noutro terminal, arrancar um segundo cliente com o mesmo comando.

4. Comandos disponíveis no cliente: TODO (registar, descobrir, enviar, levantar mensagens, enviar ficheiro).

## Estrutura do projeto

```
src/main/java/mensageiro/
├── common/
│   ├── protocol/   framing (Frame), campos (Codec), tipos de mensagem
│   └── crypto/     envelope E2E, chaves, assinaturas, KDF
├── client/
│   ├── ui/         interface de linha de comandos
│   ├── net/        ligação ao relay
│   ├── keystore/   proteção da chave privada (módulo A)
│   └── transfer/   anexos em blocos AEAD (módulo B)
└── relay/
    ├── net/        servidor TCP concorrente
    ├── auth/       registo, autenticação, diretório
    ├── store/      armazenamento diferido e autorização
    └── token/      credenciais temporárias (módulo C)

src/test/java/mensageiro/   testes (runner próprio, sem JUnit)
scripts/                    build, test, run, package
docs/                       protocolo, arquitetura, ameaças, decisões
```

## Documentação

| Ficheiro              | Conteúdo                                     |
| --------------------- | -------------------------------------------- |
| `docs/protocolo.md`   | Formato das mensagens e fluxos cliente/relay |
| `docs/arquitetura.md` | Componentes, elementos de segurança e fluxos |
| `docs/ameacas.md`     | Análise de ameaças, mitigações e limitações  |
| `docs/decisoes/`      | Decisões de segurança justificadas           |
| `docs/DIVISAO.md`     | Divisão do trabalho                          |

## Fluxo de trabalho

Ver `CONTRIBUTING.md`. Resumo: cada pessoa trabalha na sua branch, abre um Pull Request para a `main` e a outra pessoa revê antes do merge.


## Como executar

Requisitos: JDK 17 ou superior (`javac` e `java` no PATH). Em Windows usar o Git Bash. Todos os comandos a partir da raiz do repositório.

```bash
./scripts/build.sh                                  # compila para out/
./scripts/test.sh                                   # corre todos os testes
./scripts/run-relay.sh 5000                         # terminal 1: relay (cria data/relay.pub na primeira vez)
./scripts/run-client.sh 127.0.0.1 5000 data/relay.pub   # terminal 2: cliente da Alice
./scripts/run-client.sh 127.0.0.1 5000 data/relay.pub   # terminal 3: cliente do Bob
```

No cliente da Alice: `register alice` (pede uma palavra-passe e cria o cofre em `data/client/alice.vault`). No do Bob: `register bob`.
Depois, na Alice: `send bob Olá Bob!` — a mensagem aparece no terminal do Bob.
Nas execuções seguintes usa-se `login alice` (abre o cofre) em vez de `register`.
Comandos: `register <id>`, `login <id>`, `lookup <id>`, `send <id> <texto>`, `me`, `help`, `quit`.

O relay mostra a sua impressão digital no arranque; confirme-a por um canal de confiança antes de distribuir a `relay.pub`.
Na primeira vez que se fala com alguém, o cliente mostra a impressão digital dessa pessoa: compare-a por outro canal (voz, pessoalmente).
