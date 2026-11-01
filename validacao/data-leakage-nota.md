# Data Leakage Case (NIST CFReDS): nota

Correção das [respostas às cegas](data-leakage-respostas.md), publicadas no commit `6dec847`
antes de abrir o gabarito (`leakage-answers.pdf`, versão 1.32). As respostas não foram alteradas
depois de ver o gabarito. Testada com métodos e dados do NIST: isso não é uma validação feita pelo NIST.

O gabarito numera de 1 a 60 de forma diferente da minha numeração. A tabela usa a numeração dele.

## Resultado

| Situação | Perguntas | De 57 |
| --- | --- | --- |
| Certa, com o dado na tela | 20 | 35% |
| Certa, mas decodifiquei o arquivo fora do programa | 8 | 14% |
| Parcial | 20 | 35% |
| Sem resposta | 9 | 16% |

**Nota honesta do programa como está: 20 de 57 sozinho, 28 de 57 com trabalho manual.** As perguntas 58 a 60
(linha do tempo, metodologia e diagrama) pedem a redação de quem examina e não entram na conta.

O teste foi feito **sem a linha do tempo completa**, de propósito. Parte das lacunas de atalhos, ShellBags,
diário USN, listas de atalhos e histórico do Internet Explorer pode ser coberta por ela. Isso não foi medido
neste caso.

## Pergunta por pergunta

| Nº | Assunto | Situação | Observação |
| --- | --- | --- | --- |
| 1 | Hashes | Parcial | Os 4 MD5 conferem. SHA-1 do conteúdo não é calculado. O registro não diz de qual imagem é o hash. |
| 2 | Partições | Parcial | Início certo. Falta tamanho e tipo. |
| 3 | Sistema | Certa | |
| 4 | Fuso | Certa | |
| 5 | Nome do computador | Certa | |
| 6 | Contas | Parcial | Falta a contagem de logons. |
| 7 | Último usuário | Certa | |
| 8 | Desligamento | Certa | 15:31:05 UTC é o mesmo instante de 11:31:05 local. |
| 9 | Rede | Parcial | Falta o nome da placa. |
| 10 | Programas instalados | Certa | |
| 11 | Execução | Parcial | Prefetch sem contagem. Faltaram entradas de Shimcache e MuiCache na resposta. |
| 12 | Liga, desliga, logon | Parcial | Os eventos estão no caso. Minha resposta omitiu 22/03 e os logons não interativos. |
| 13 | Navegadores | Certa | Versão não foi pedida. |
| 14 | Caminhos | Certa | |
| 15 | Sites | Parcial | Chrome completo. Internet Explorer 11 sem URL. |
| 16 | Termos pesquisados | Parcial | Chrome certo, com um termo que deixei passar (`data recovery tools`). As buscas no Bing, pelo Internet Explorer, ficaram de fora. |
| 17 | Busca no Explorer | Certa | Eu tinha marcado parcial, mas `secret` era a resposta inteira. |
| 18 | Programa de e-mail | Certa | |
| 19 | Arquivo de e-mail | Certa | |
| 20 | Conta de e-mail | Certa | |
| 21 | E-mails | Parcial | Assuntos e pastas certos, e o apagado `It's me` foi achado. Falta data, remetente, destinatário, corpo e anexo. |
| 22 | Dispositivos | Parcial | Séries e rótulo certos. Falta a data da primeira conexão. |
| 23 | Renomeações | Sem resposta | Depende do diário USN. |
| 24 | IP do compartilhamento | Certa | |
| 25 | Pastas da RM#2 | Parcial, manual | Só 1 de 6 pastas. Depende de ShellBags. |
| 26 | Arquivos da RM#2 | Certa, manual | |
| 27 | Pastas do compartilhamento | Parcial, manual | Faltaram `Common Data`, `Past Projects`, `design`, `technical review`, `proposal` e `progress`. |
| 28 | Arquivos do compartilhamento | Certa | Os dois aparecem no histórico do Office. Eu tinha marcado um como manual sem necessidade. |
| 29 | Nuvem | Certa | |
| 30 | Apagados do Drive | Certa, manual | Ver a observação sobre o gabarito. |
| 31 | Conta do Drive | Certa, manual | |
| 32 | Como gravou o CD-R | Certa, manual | |
| 33 | Quando gravou | Parcial | **Minha falha de leitura.** O caso tem os eventos 133 do leitor às 19:47:47, 19:56:11, 20:24:46 e 20:41:21 UTC, iguais aos do gabarito. Procurei pelo nome errado e respondi outras horas. O programa mostra só "Evento 133", sem dizer o que significa. |
| 34 | Copiados para o CD-R | Parcial | Faltou a pasta `de` e os nomes dentro das pastas. Citei itens a mais. |
| 35 | Abertos do CD-R | Certa, manual | |
| 36 | Datas da demissão | Parcial | Datas do NTFS certas. Faltam as internas do documento. |
| 37 | Impressão | Certa | |
| 38 | Thumbcache | Certa | |
| 39 | Miniaturas | Sem resposta | |
| 40 | Local das notas | Certa | |
| 41 | Conteúdo das notas | Certa, manual | |
| 42 | Busca do Windows | Certa | |
| 43 | Tipos de dados no banco | Parcial | Faltaram histórico do Internet Explorer, menu Iniciar e notas. |
| 44 | Internet Explorer no banco | Sem resposta | |
| 45 | E-mails no banco | Sem resposta | |
| 46 | Área de Trabalho no banco | Sem resposta | |
| 47 | Cópias de sombra | Parcial | Local certo. Citei três arquivos e horário 3 segundos diferente para a cópia. |
| 48 | Drive na cópia de sombra | Sem resposta | |
| 49 | `cloud_entry` na cópia | Sem resposta | |
| 50 | Outlook fora da cópia | Certa | |
| 51 | Lixeira | Certa, manual | Os 14 itens e horários conferem. |
| 52 | Antiforense no PC | Parcial | Instalação e uso certos. Faltam buscas, alvos do Eraser, saída da conta do Drive e e-mails apagados. |
| 53 | Recuperar da RM#2 | Parcial | Os 17 arquivos aparecem, com o tipo real. A recuperação de cada um não foi testada. |
| 54 | Antiforense na RM#2 | Certa, manual | Formatação inferida. |
| 55 | Copiados para a RM#2 | Parcial | Inferência certa, sem a lista por arquivo. |
| 56 | Recuperar do CD-R | Sem resposta | Imagem não lida. |
| 57 | Antiforense no CD-R | Sem resposta | Imagem não lida. |

## O que o teste revelou

1. **Imagem de CD-R não é lida.** O disco usa UDF, formato que a leitura atual não reconhece. O aviso diz "possível criptografia", o que engana: não há sinal de criptografia aqui. O exame profundo também só listou a imagem, sem recuperar nada.
2. **Sem atalhos, listas de atalhos e ShellBags decodificados.** É a maior causa de resposta manual ou parcial.
3. **Diário USN e `$LogFile` não são lidos.** Sem eles não há renomeações nem a lista completa do que foi para o CD-R.
4. **E-mails sem conteúdo.** O exame profundo lê os e-mails, mas a importação traz só o caminho.
5. **Histórico do Internet Explorer 11 sem URL.** São 10.209 entradas de `WebCacheV01.dat` que não dizem qual site.
6. **`Windows.edb` e cópias de sombra não são abertos.** Respondem por seis perguntas sem resposta.
7. **Lixeira, Prefetch e eventos com pouca informação.** `$I` não é decodificado, a data do `$R` aparece como 2076, o Prefetch vem sem contagem e "Evento 133" não explica que é um CD gravado.
8. **Hash incompleto.** Falta SHA-1 do conteúdo, o nome da imagem no registro e a comparação com o hash gravado no E01.
9. **Conteúdo interno de arquivos.** A tela não abre o conteúdo de itens do exame profundo, como e-mails e relatórios.

## Observações sobre o gabarito

- Na pergunta 30, a tabela troca as datas de modificação dos dois arquivos. O próprio log citado nas considerações e a pergunta 49 confirmam: `happy_holiday.jpg` é de 2015-01-29 e `do_u_wanna_build_a_snow_man.mp3` é de 2015-01-30, como respondi.
- Na pergunta 33, o texto cita o evento 113, mas nas mesmas horas o log tem o evento 133 do leitor `CdRom0`.
- Na pergunta 19, a resposta diz `Microsoft\Office`, e as considerações dele dizem `Microsoft\Outlook`, que é o caminho real.

## Segunda rodada, depois das correções

**Esta rodada não é às cegas.** As correções foram feitas depois de ver o gabarito, então ela mede se as lacunas fecharam, não a capacidade em um caso novo. A nota às cegas continua sendo a de cima: 20 de 57. O próximo teste que vale como independente precisa de outro caso.

O caso foi processado do zero, sem a linha do tempo completa: 188 leituras, nenhuma falha, cerca de 54 minutos (34 da análise e 19 do exame profundo) e 20 GB.

| Situação | Perguntas | De 57 |
| --- | --- | --- |
| Dado na tela confere com o gabarito | 49 | 86% |
| Parcial | 5 | 9% |
| Sem resposta | 3 | 5% |

A conferência foi feita pelo banco do caso, comparando cada resposta com o gabarito, com busca e abertura do caso conferidas no navegador. As 49 ainda pedem interpretação de quem examina, como a 34, respondida pela imagem do CD-R embora o gabarito peça só o PC, e a 52, em que o alvo do Eraser sai dos nomes no diário do NTFS.

**Continuam parciais:**

- 6: falta a contagem de logons por conta.
- 9: falta o nome da placa de rede.
- 33: os quatro eventos de gravação conferem, mas a gravação como pendrive, das 16:53 às 16:58 locais, não tem data.
- 36: faltam as datas internas do documento.
- 47: as cópias de sombra aparecem como arquivos, sem os metadados de cada cópia.

**Continuam sem resposta:**

- 39: as miniaturas não são extraídas.
- 48 e 49: o conteúdo das cópias de sombra não é montado, o que depende de uma ferramenta ainda não liberada.

**O que mudou:**

- Novas leituras: atalhos, listas de atalhos, pastas navegadas, lixeira, inclusive esvaziada, e diário do NTFS.
- E-mails com data, remetente, destinatário, pasta e corpo. Histórico do Internet Explorer com URL. Banco da busca do Windows lido.
- CD-R em UDF: entradas de diretório, inclusive as apagadas, e os 17 documentos recuperados por assinatura, com os tamanhos do gabarito. Doze trazem o nome original no próprio arquivo ou o tipo certo; os formatos antigos do Office só trazem trechos de texto.
- RM#2: os 17 arquivos apagados foram lidos com o tamanho exato do gabarito.
- Hash com SHA-1, nome da imagem e comparação com o hash gravado no E01. Os quatro conferem. Partições com tamanho.
- Corrigido um erro encontrado no caminho: em um caso com várias imagens, abrir um arquivo lia sempre a primeira imagem.
