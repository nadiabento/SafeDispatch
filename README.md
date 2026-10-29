# SafeDispatch — Mensageiro Seguro # 

Sistema de mensagens seguras cliente-servidor com cifra de ponta a ponta (E2E), armazenamento diferido e controlo de acessos baseado em credenciais temporárias. Desenvolvido no âmbito da unidade curricular de Segurança Informática da Universidade de Aveiro.

O projeto é implementado de raiz em Java nativo, utilizando exclusivamente primitivas da Java Cryptography Architecture (JCA) e sockets TCP, sem qualquer recurso a bibliotecas de mensagens, frameworks externas ou à serialização nativa de Java (`ObjectInputStream`).

---

## 🎯 Âmbito e Módulos do Grupo (Grupo 5)

Para além do núcleo comum (registo, descoberta, cifra híbrida e reencaminhamento), o sistema integra três extensões específicas:

* **Módulo A (Proteção da Chave Privada no Cliente):** A chave privada nunca reside em claro no disco. O cofre local (`KeyVault`) utiliza derivação por PBKDF2 com parâmetros justificados, autenticação de integridade (AEAD/HMAC) e mecanismo de atraso crescente (rate limiting) após falhas consecutivas de autenticação.
* **Módulo B (Anexos Grandes Cifrados por Blocos):** Transferência de ficheiros de grandes dimensões processada em fluxo (*streaming*, sem carregamento integral para memória), dividida em blocos protegidos com AEAD, nonces derivados de contadores e deteção rigorosa de blocos reordenados, removidos, alterados ou truncados.
* **Módulo C (Credenciais Temporárias no Relay):** Emissão de tokens de curta duração e âmbito restrito (levantamento exclusivo de mensagens próprias) assinados/autenticados pelo relay, com ciclo de vida, expiração e renovação.

---

## 📂 Organização do Repositório

```text
.
├── docs/                        # Documentação de arquitetura, ameaças e decisões
│   ├── arquitetura.md           # Desenho do sistema e componentes
│   ├── ameacas.md               # Modelo e matriz de análise de ameaças
│   ├── protocolo.md             # Especificação do protocolo binário de rede
│   ├── DIVISAO.md               # Repartição de tarefas e planeamento
│   └── decisoes/                # Architecture Decision Records (ADRs)
├── scripts/                     # Scripts utilitários de compilação e execução
│   ├── build.sh                 # Compilação do código-fonte para out/
│   ├── test.sh                  # Execução dos testes automatizados
│   ├── run-relay.sh             # Inicialização do servidor Relay
│   ├── run-client.sh            # Inicialização da interface CLI do Cliente
│   └── package.sh               # Geração do arquivo zip de submissão
├── src/
│   ├── main/java/mensageiro/
│   │   ├── client/              # CLI, cofre de chaves (Módulo A) e streaming (Módulo B)
│   │   ├── common/              # Criptografia partilhada e enquadramento de frames/codec
│   │   └── relay/               # Servidor multithread, armazenamento e tokens (Módulo C)
│   └── test/java/mensageiro/    # Mini TestRunner nativo e suites de teste (sem dependências)
├── CONTRIBUTING.md              # Convenções de Git, branches e commits
└── README.md