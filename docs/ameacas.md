# Análise de ameaças — versão 1 (Entrega 1)

> Rascunho em Markdown para passar para o modelo do docente.

## 1. Ativos, atores e pressupostos

**Ativos**: conteúdo das mensagens; identidade e autoria; chaves privadas dos utilizadores; diretório de chaves públicas; disponibilidade do relay.

**Atores**
- *Relay curioso ou comprometido*: vê todo o tráfego e controla o diretório; tenta ler ou alterar mensagens, ou trocar chaves.
- *Atacante de rede*: observa, repete, altera ou injeta tráfego; pode fazer-se passar pelo relay.
- *Utilizador malicioso*: registado, tenta passar por outro, ou ler mensagens que não são para ele.
- *Quem tem acesso ao disco*: copia ficheiros do cliente (cofre).

**Pressupostos**
- As máquinas dos clientes não estão comprometidas.
- As primitivas da JCA (Ed25519, X25519, AES-GCM, SHA-256, PBKDF2) são seguras.
- O utilizador obtém a `relay.pub` por um canal de confiança e consegue comparar impressões digitais por outro canal.
- Fora de âmbito: ataques ao SO do cliente, canais laterais, negação de serviço distribuída.
- Esta versão não protege os metadados (quem fala com quem, quando, tamanho): o relay vê-os.

## Tabela de ameaças (cliente e criptografia)

| # | Ameaça | Mitigação | Teste |
|---|---|---|---|
| 1 | Relay ou atacante lê o conteúdo | Cifra híbrida; só o destinatário tem a chave privada X25519 | `EnvelopeTest.testTextoEmClaroNaoAparece`, `testTerceiroNaoConsegueAbrir`, `ClientFlowTest.testAliceEnviaBobRecebe` |
| 2 | Alteração do envelope em trânsito | GCM + assinatura Ed25519; cabeçalho como AAD | `EnvelopeTest.testAlterarQualquerBitDetetado`, `testTruncadoOuBytesAMaisRecusado` |
| 3 | Falsificação de remetente | Verificação da assinatura antes de decifrar, contra a chave do remetente esperado | `EnvelopeTest.testAssinaturaDeOutraPessoaRecusada`, `testNinguemReclamaAutoria` |
| 4 | Registar a chave de outra pessoa | Prova de posse (assinatura de id + chaves) | `ProofsTest.testRegisterAdulteradoRecusado`, `ClientFlowTest.testRegistrationAdulteradaRecusada` |
| 5 | Relay troca as chaves de um utilizador na pesquisa | Prova de registo verificada pelo cliente; impressão digital; fixação à primeira utilização | `ClientFlowTest.testRelayTrocaChave`, `testChavesMudam` |
| 6 | Repetição de um envelope pelo relay | `msgId` aleatório; descarte de repetidos | `ClientFlowTest.testRepeticaoDescartada` |
| 7 | Envelope entregue à pessoa errada | Destinatário no cabeçalho autenticado; a chave de decifra só existe no destinatário | `ClientFlowTest.testEnvelopeDeOutro` |
| 8 | Repetir uma autenticação antiga | Nonce aleatório de uso único; etiqueta de contexto própria | `ProofsTest.testAuthValidoEAdulterado`, `testRegisterNaoServeComoAuth`, `ClientFlowTest.testAuthChaveErrada` |
| 9 | Servidor falso a fazer-se passar pelo relay | O relay assina o nonce; o cliente verifica com a `relay.pub` antes de responder | `ClientFlowTest.testRelayFalso`, `testRelayChallenge` |
| 10 | Cofre copiado ou lido do disco | PBKDF2 (600 000 iterações) + AES-GCM; nada em claro | `KeyVaultTest.testFicheiroSemChavePrivadaEmClaro`, `testPasswordErradaRecusada` |
| 11 | Cofre alterado ou truncado | GCM com o cabeçalho como AAD; tecto de iterações | `KeyVaultTest.testAlterarQualquerByteDetetado`, `testFicheiroTruncadoOuLixoRecusado` |

**Limitações conhecidas (Entrega 1)**
- Na primeira mensagem com um contacto novo, só a comparação da impressão digital por outro canal protege contra um relay que engane ambos desde o início.
- O descarte de repetidos é só em memória: perde-se ao reiniciar o cliente, e não há janela de validade pelo timestamp.
- O cofre ainda não tem atraso crescente após falhas (Entrega 2); o atraso, de qualquer forma, não trava um ataque offline ao ficheiro copiado.
- As chaves dos contactos fixadas (`Contacts`) vivem só em memória.

## Ameaças do relay **[Nadia]**
(Disponibilidade, controlo de acesso, metadados.)
