# Resultado do teste às cegas: Windows Server 2022

As respostas estão em [server2022-respostas.md](server2022-respostas.md) e foram publicadas no commit `ad43cd8`, antes de abrir o README do caso.

## Não há nota de acerto

O README do caso não é um gabarito. O autor deixa a análise como exercício e só entrega as respostas certas ("ground truth") por pedido direto, para pesquisa. Sem isso, um número de acertos seria inventado.

## O que o README permite conferir

| Pergunta | O que o README diz | Situação |
|---|---|---|
| 1 | Escritório simulado no Reino Unido | Coerente com o fuso `GMT Standard Time` |
| 4 | O administrador abriu o RDP para trabalhar de casa | Coerente com separar `195.21.1.97` (`ADMIN-WFH`) do invasor, mas não confirma os IPs |
| 13 e 14 | Em 12/02/2024, o servidor parou de responder e mostrava "Red Petya" | **Não confirma.** Respondi `rename.exe` e 09/02 21:46:24 pelo contexto. O servidor nunca mostrou o Red Petya nos dados, e a mensagem no disco assina Ryuk |
| 20 | Peritos decifraram o disco antes de gerar a imagem | Explica a pergunta, que ficou sem resposta |

As outras 15 perguntas ficam sem conferência externa.

## O que o teste revelou no programa

| Achado | Decisão |
|---|---|
| A análise levou 2h32, e `bulk_extractor` sozinho levou 72 minutos, sem deixar nada aparecer enquanto rodava | Movido para o exame profundo |
| O comando da tarefa maliciosa, a melhor prova do caso, só saiu abrindo o arquivo à mão | As tarefas agendadas agora viram registros com autor, gatilho e comando, e programa em pasta de usuário vira alerta |
| Conexões de rede saíam como "( bytes enviados, recebidos)" | Corrigido: conexão sem conteúdo não tem o campo que era lido, e o novo campo existe sempre |
| Nada separa sozinho o administrador do invasor, nem resume o ataque | Nova aba Acessos, com origens, contas, falhas, entradas e a sequência dos fatos. Ela mostra os fatos, mas não diz quem é o invasor |
| `dir.exe` e `rename.exe` não dispararam nenhuma assinatura, e um servidor sem Prefetch nem auditoria de processos não prova execução | **Limite conhecido** |

Dois itens que publiquei como falha antes de abrir o README foram revistos:

- As datas vazias na rede não são erro. Os pacotes foram recuperados do disco e vêm com a data zerada, então não há data a mostrar.
- A criação depois da mudança não virou alerta. A comparação disparou 1.130 vezes no Data Leakage e 207 aqui, quase tudo em arquivos normais do Windows.

O histórico do navegador parar em 05/02 23:41 também não foi confirmado como falha: não achei nada indicando navegação depois disso, e o FTP passou pelo Explorer.

## Segunda rodada, com as correções

A mesma imagem, em um caso novo e do zero, sem falhas em nenhum módulo:

| Etapa | Antes | Depois |
|---|---|---|
| Análise padrão | 152 minutos | 83 minutos |
| Exame profundo | Não rodou, por falta de espaço | 144 minutos, dos quais 79 nos vestígios do disco e 60 no exame de conteúdo |
| Tarefas agendadas | Nenhum registro | 154 registros, com `\Enterpries backup` como o único alerta e o comando completo |
| Conexões de rede | Sem bytes | 226 conexões, todas com bytes |

Os tempos são de uma única execução em cada lado, sem controle do que mais rodava na máquina. A correção desloca os vestígios do disco para o exame profundo, então o total não caiu: quem roda os dois ainda espera 3h47.

## Aba Acessos

Criada depois do teste, vendo este caso, então ela também não vale como teste às cegas. Mostra de novo, sem script, o que eu tinha montado à mão: as 100.003 falhas de `36.133.110.87`, a primeira entrada às 10:55:56, depois de 52.426 falhas, a conta `admin` e a tarefa com o comando completo.

O caso também mostrou um limite. As mudanças na conta `admin` saíram em uma sessão antiga do sistema (`0x81BFAB`), sem nenhuma entrada no log, então os dados não ligam essas mudanças a um IP. A tela cita a última entrada remota na conta, `185.229.66.183`, e diz que isso não prova a autoria. A ligação direta pela sessão foi testada só com dados de teste.

Só entram os eventos 4624, 4625 e 1149 do Windows, e as sessões 21 e 25 do RDP ainda não são lidas. No Data Leakage, sem acesso remoto, a aba lista só as contas criadas.

## Conclusão

Com os dados do programa deu para montar a história inteira: 100 mil tentativas de senha, entrada, conta nova em Domain Admins, ferramentas baixadas, FTP e lançamento por PsExec. Mas essa montagem foi minha, consultando o banco por script, e o resultado não vale como medida de acerto. O teste serviu para achar falhas, e não para medir a precisão do programa.
