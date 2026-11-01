# Data Leakage Case (NIST CFReDS): respostas às cegas

Respostas às 60 perguntas do caso, gravadas e publicadas **antes** de abrir o gabarito.
A nota, quando existir, fica em outro commit, para que o histórico mostre o que foi
respondido sem ver a resposta.

## Condições do teste

- Caso processado com análise padrão e exame profundo, sem a linha do tempo completa
  (interrompida de propósito para este teste).
- 162 leituras, nenhuma falha. A imagem `rm#3` não foi lida.
- Todas as datas em UTC. O fuso da máquina é UTC-5, com horário de verão UTC-4 nas datas do caso.

## Como cada resposta foi obtida

| Marca | Significado |
| --- | --- |
| **direta** | Está nos registros que o programa mostra. |
| **manual** | O programa entrega o arquivo, mas decodifiquei ou interpretei o conteúdo fora dele. Não conta como mérito do programa. |
| **parcial** | Só parte do que foi pedido. |
| **não responde** | O programa não entrega o necessário. |

## Sistema (1 a 13)

**1. Hashes das imagens.** Parcial. MD5 do conteúdo, nesta ordem de leitura (a ordem é inferência, o registro não diz o nome da imagem): PC `a49d1254c873808c58e6f1bcd60b5bde`, RM#1 `8bfa4230bf4e35db966b8c1a9321a0b1`, RM#2 `b4644902acab4583a1d0f9f1a08faa77`, RM#3 `df914108fb3d86744eb688eba482fbdf`. SHA-1 do conteúdo não é calculado, só SHA-256. MD5 e SHA-1 existem por arquivo de segmento.

**2. Hash de aquisição confere com o de verificação?** Não responde. O programa calcula o hash do conteúdo, mas não mostra o hash gravado dentro do E01 para comparar.

**3. Partições do PC.** Parcial. Duas partições NTFS, nos setores 2048 e 206848. O tamanho e o tipo de cada uma não aparecem.

**4. Sistema operacional.** Direta. Windows 7 Ultimate, Service Pack 1, build 7601. Instalado em 2015-03-22 14:34:26 UTC. Proprietário registrado: `informant`. Organização vazia.

**5. Fuso horário.** Direta. Eastern Standard Time (Bias 300, ActiveTimeBias 240).

**6. Nome do computador.** Direta. INFORMANT-PC.

**7. Contas.** Parcial. `informant` (1000, criada 2015-03-22 14:33:54, último logon 2015-03-25 14:45:59), `admin11` (1001, criada 2015-03-22 15:51:54, último logon 2015-03-22 15:57:02), `ITechTeam` (1002, criada 2015-03-22 15:52:30, sem logon), `temporary` (1003, criada 2015-03-22 15:53:01, último logon 2015-03-22 15:55:57). A contagem de logons não veio: contei pelo evento 4624 interativo, o que é aproximação.

**8. Último usuário a entrar.** Direta. `informant` (LastLoggedOnUser `.\informant`, logon 2015-03-25 14:45:59).

**9. Último desligamento registrado.** Direta. 2015-03-25 15:31:05 UTC (ShutdownTime).

**10. Interface com IP por DHCP.** Direta. IP 10.11.11.129, máscara 255.255.255.0, gateway e DNS 10.11.11.2, servidor DHCP 10.11.11.254, domínio `localdomain`, concessão obtida em 2015-03-25 15:19:50 e válida até 15:49:50. Nome e GUID da placa não conferidos.

**11. Programas instalados depois do sistema.** Direta. Microsoft Office Professional Plus 2013 (2015-03-22), Google Chrome 41 (2015-03-22), Internet Explorer 11 (2015-03-22), Google Drive 1.20 (2015-03-23), iCloud com Bonjour, Apple Application Support e Apple Software Update (2015-03-23), Microsoft .NET Framework 4 (2015-03-25), Eraser 6.2 (2015-03-25), CCleaner 5.04 (2015-03-25).

**12. Execução de programas.** Parcial. Caminho e data da última execução vêm do Prefetch. A contagem vem do UserAssist, mas só para o que é aberto pela interface, porque a leitura do Prefetch não traz a contagem de execuções. Destaques: `Eraser 6.2.0.2962.exe` 14:50:14, `ccsetup504.exe` 14:57:56, `Eraser.exe` 15:13:30, `CCleaner64.exe` 15:15:50, `CCleaner\uninst.exe` 15:18:29, `googledrivesync.exe` 15:21:31, `WINWORD.EXE` 15:24:48, `xpsrchvw.exe` 15:28:47, todos em 2015-03-25.

**13. Liga, desliga, logon e logoff entre 09:00 e 18:00 locais.** Direta. Em UTC, início de sessão e fim: 2015-03-23 início 17:24:23, logon 17:24:41 e logoff 21:02:53, desligamento 21:03:12 (a parte depois de 18:00 locais fica fora da janela); 2015-03-24 início 13:21:29, logon 13:21:44, desbloqueio 18:28:38, logoff 21:07:25, desligamento 21:07:29; 2015-03-25 início 10:15:35 (reinícios às 10:19:26 e 13:05:41), logon 13:06:08, desbloqueio 14:45:59, desligamento 15:31:05.

## Navegação e e-mail (14 a 22)

**14. Navegadores usados.** Direta. Internet Explorer e Google Chrome.

**15. Caminhos do histórico.** Direta. Chrome: `Users\informant\AppData\Local\Google\Chrome\User Data\Default\History`. Internet Explorer 11: `Users\informant\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`. Há ainda os mesmos arquivos em `admin11` e `temporary`.

**16. Sites acessados.** Direta para o Chrome, parcial para o Internet Explorer (as entradas aparecem, mas sem URL fácil de ler). Exemplos: sans.org sobre vazamento de dados (2015-03-23 18:02:18), emirates247 (18:04:54), mediapost (18:05:28), fbi.gov sobre propriedade intelectual (18:05:55), forensicswiki sobre antiforense (18:17:19), defcon.org antiforense (18:18:00), apple.com/icloud (19:55:18), google.com/drive (19:56:08).

**17. Termos pesquisados.** Direta. `outlook 2013 settings`, `comapny`, `Emmy Noether`, `data leakage methods`, `leaking confidential information`, `information leakage cases`, `intellectual property theft`, `how to leak a secret`, `cloud storage`, `digital forensics`, `how to delete data`, `anti-forensics`, `system cleaner` (a parte do meio da URL ficou cortada, conferir), `how to recover data`, `google`, `apple icloud`, `google drive`, `security checkpoint cd-r`.

**18. Termos no Explorer.** Parcial. Só `secret` (WordWheelQuery, 2015-03-23 18:40:17). O valor completo com outros termos pode existir na chave, mas a leitura mostra só o primeiro.

**19. Programa de e-mail.** Direta. Microsoft Outlook 2013.

**20. Onde está o arquivo de e-mail.** Direta. `Users\informant\AppData\Local\Microsoft\Outlook\iaman.informant@nist.gov.ost`.

**21. Conta de e-mail.** Direta. iaman.informant@nist.gov.

**22. E-mails.** Parcial. Assunto e pasta aparecem: Inbox `Hello, Iaman`, `Good job, buddy.`, `Important request`, `Last request`, `RE: Good job, buddy.`; Sent Items `RE: Hello, Iaman`, `RE: Important request`; Deleted Items `RE: It's me`, `RE: Watch out!`, `RE: Last request`, `Done`; recuperada `It's me` (marcada como apagada). Data, remetente, destinatário, corpo e anexos não chegam ao programa.

## Dispositivos, rede e arquivos abertos (23 a 29)

**23. Dispositivos externos.** Direta. Dois SanDisk Cruzer Fit (VID_0781 PID_5571), séries `4C530012450531101593` e `4C530012550531106501`, um deles com rótulo `IAMAN $_@` no E:. Data da primeira conexão não extraída, só a da última escrita da chave. Há também o leitor de CD virtual VMware.

**24. Renomeações na Área de Trabalho, de 23 a 24/03/2015.** Não responde. O diário USN é reconhecido, mas o relatório dele não é lido para o caso.

**25. IP do compartilhamento da empresa.** Direta. 10.11.11.128 (`\\10.11.11.128\secured_drive`, mapeado como V:).

**26. Pastas percorridas na RM#2.** Manual. `E:\Secret Project Data\design` e o nome `winter_whether_advisory.zip` nas listas de atalhos. Sem ShellBags, a lista é incompleta.

**27. Arquivos abertos na RM#2.** Manual. `E:\Secret Project Data\design\winter_whether_advisory.zip`. A separação entre RM#1 e RM#2 é inferência: as duas foram montadas como E:, e separo pelo caminho.

**28. Pastas percorridas no compartilhamento.** Manual. `\\10.11.11.128\secured_drive\Secret Project Data`, `\pricing decision`, `\final`. Sem ShellBags, a lista é incompleta.

**29. Arquivos abertos no compartilhamento.** Direta para o primeiro, manual para o segundo. `(secret_project)_pricing_decision.xlsx` (2015-03-23 20:26:53) e `[secret_project]_final_meeting.pptx` (20:27:33). A lista pode estar incompleta sem ShellBags.

## Nuvem, CD-R e documento (30 a 38)

**30. Serviços de nuvem.** Direta. Google Drive (`AppData\Local\Google\Drive\user_default`: `sync_log.log`, `snapshot.db`, `sync_config.db`) e iCloud (`icloudsetup.exe`, `Common Files\Apple\Internet Services\iCloud.exe`).

**31. Arquivos apagados do Google Drive.** Manual. Pelo `sync_log.log`, horário UTC: `How to get started with Drive` (2015-03-23 20:06:05), `do_u_wanna_build_a_snow_man.mp3` e `happy_holiday.jpg` (2015-03-23 20:42:17). Datas de modificação no log: `happy_holiday.jpg` 1422563714 (2015-01-29 20:35:14 UTC), `do_u_wanna_build_a_snow_man.mp3` 1422636560 (2015-01-30 16:49:20 UTC).

**32. Conta do Google Drive.** Manual. iaman.informant.personal@gmail.com.

**33. Como gravou o CD-R.** Manual. Pelo próprio Windows, usando a pasta de gravação do Explorer (`AppData\Local\Microsoft\Windows\Burn\Burn`). Conclusão inferida pelos caminhos na lixeira e pelo leitor `BD-RE Drive (D:)`.

**34. Quando gravou.** Manual, por inferência. Em 2015-03-24: pasta de gravação em uso até 19:51:47 (itens enviados à lixeira), segunda leva até 20:11:42, última alteração da pasta às 20:43:20, CD `IAMAN CD` em uso a partir de 20:44:18. O evento exato da gravação não foi encontrado.

**35. O que foi copiado para o CD-R.** Parcial. Pela lixeira da pasta de gravação: pastas `prop` (41,7 MB), `pd` (21,9 MB), `tr` (5,1 MB), `prog` (4,5 MB), mais `IE11-Windows6.1-x64-en-us.exe` e as imagens de exemplo do Windows. Os nomes individuais dependem do diário do NTFS, que o programa não lê. Pode ser que parte tenha ido só para a pasta, sem gravar.

**36. O que foi aberto do CD-R.** Manual. `D:\de\winter_whether_advisory.zip` (2015-03-24 20:44:18), `D:\Penguins.jpg` (21:01:10), `D:\Koala.jpg` (21:01:12), `D:\Tulips.jpg` (21:01:14), volume `IAMAN CD`.

**37. Datas do arquivo de demissão.** Direta. `Users\informant\Desktop\Resignation_Letter_(Iaman_Informant).docx`: criado 2015-03-24 18:48:40, alterado 18:59:30, acessado 18:59:30. Última abertura pelo Word 2015-03-25 15:24:49.

**38. Como e quando imprimiu.** Direta. Pela impressora Microsoft XPS Document Writer, gerando `Desktop\Resignation_Letter_(Iaman_Informant).xps` em 2015-03-25 15:28:33 (concluído às 15:28:34), depois aberto no Visualizador XPS às 15:28:47.

## Miniaturas, notas e busca do Windows (39 a 48)

**39. Onde fica o Thumbcache.** Direta. `Users\<usuário>\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db`.

**40. Miniaturas de arquivos confidenciais em `thumbcache_256`.** Não responde. O arquivo é listado, mas as miniaturas não são extraídas.

**41. Onde ficam as notas.** Direta. `Users\informant\AppData\Roaming\Microsoft\Sticky Notes\StickyNotes.snt`.

**42. Conteúdo das notas.** Manual. "Tomorrow..." e "Everything will be OK...".

**43. Busca e indexação do Windows ligadas?** Parcial, por inferência. Sim: serviço WSearch presente, `SearchIndexer.exe` executado (2015-03-25 10:17:57) e `Windows.edb` alterado em 2015-03-25 13:06:17. O valor `Start` do serviço não aparece na leitura.

**44. Caminho do banco.** Direta. `ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`.

**45. Que dados há no banco.** Parcial. As tabelas são listadas (`SystemIndex_0A`, `SystemIndex_0P`, `SystemIndex_Gthr`, `SystemIndex_GthrPth`) e há colunas de mensagem, como `System_Message_ConversationIndex`, o que indica e-mails além de arquivos. Sem leitura do conteúdo.

**46. Internet Explorer no banco, de 22 a 23/03/2015.** Não responde.

**47. E-mails no banco, de 23 a 24/03/2015.** Não responde.

**48. Área de Trabalho no banco.** Não responde.

## Cópias de sombra (49 a 53)

**49. Onde ficam e quando foram criadas.** Direta. `\System Volume Information\`. Arquivos `{3808876b-c176-4e48-b7ae-04046e6cc752}` (2015-03-25 14:50:37), `{9b365807-d2ef-11e4-b734-000c29ff2429}{3808876b-...}` (criado 14:50:37, alterado 14:57:27) e `{9b365826-d2ef-11e4-b734-000c29ff2429}{3808876b-...}` (14:57:24). A data é dos arquivos: os metadados da cópia não são lidos.

**50. Google Drive na cópia de sombra.** Não responde. O conteúdo das cópias não é montado.

**51. Diferença entre o sistema atual e a cópia.** Não responde.

**52. Registros apagados de `cloud_entry` na cópia.** Não responde.

**53. Por que não há e-mail do Outlook na cópia.** Direta. A chave `FilesNotToSnapshot` exclui `$UserProfile$\AppData\Local\Microsoft\Outlook\*.ost`.

## Lixeira e antiforense (54 a 57)

**54. Lixeira.** Manual. Em `$Recycle.Bin\S-1-5-21-2425377081-3129163575-2985601102-1000` (usuário `informant`), todos vindos de `Burn\Burn`: às 2015-03-24 19:51:47 as pastas `prop`, `pd`, `tr`, `prog`; às 20:11:42 `IE11-Windows6.1-x64-en-us.exe`, `desktop.ini` e as imagens `Chrysanthemum`, `Desert`, `Hydrangeas`, `Jellyfish`, `Koala`, `Lighthouse`, `Penguins`, `Tulips`. A data no registro do arquivo `$R` aparece errada (2076), e o programa não decodifica o `$I` por conta própria.

**55. Antiforense no PC em 2015-03-25.** Direta. Instalou Eraser (14:50:14) e CCleaner (14:57:56), usou o Eraser (aberto 15:12:28, configurado 15:13:08, executado 15:13:30) e o CCleaner (15:15:50), desinstalou o CCleaner (15:18:29). Os arquivos de contexto foram apagados ou sobrescritos. O alvo do Eraser não é identificado.

**56. Recuperar os apagados da RM#2.** Parcial. 50 itens listados, sem arquivos ativos: `design\winter_storm.amr`, `design\winter_whether_advisory.zip`; `PRICIN~1\my_favorite_cars.db`, `my_favorite_movies.7z`, `new_years_day.jpg`, `super_bowl.avi`; `progress\my_friends.svg`, `my_smartphone.png`, `new_year_calendar.one`; `proposal\a_gift_from_you.gif`, `landscape.png`; `TECHNI~1\diary_#1d.txt` até `diary_#3p.txt`, e 24 imagens na raiz. A classificação por assinatura mostra que as extensões são falsas: `diary_#1p.txt` é apresentação, `my_favorite_cars.db` é planilha, `landscape.png` é documento. Os conteúdos individuais só foram listados, não comparados.

**57. Antiforense na RM#2.** Parcial, por inferência. Renomeou arquivos confidenciais com nomes inofensivos e extensões falsas, e formatou ou apagou o volume, deixando tudo em `$OrphanFiles`.

## Cópia para RM#2 e CD-R (58 a 60)

**58. O que foi copiado do PC para a RM#2.** Parcial, por inferência. A estrutura `design`, `pricing decision`, `progress`, `proposal`, `technical review` (`TECHNI~1`) coincide com `Secret Project Data` da RM#1 e do compartilhamento, com os arquivos renomeados. Não há comparação arquivo a arquivo.

**59. Recuperar os ocultos do CD-R RM#3.** Não responde. A imagem não foi lida: o sistema de arquivos não foi reconhecido e a alta entropia foi tratada como possível criptografia.

**60. Antiforense no CD-R RM#3.** Não responde, pela mesma razão. Só uma hipótese: `D:\de\winter_whether_advisory.zip`, com o mesmo nome visto na RM#2, sugere o mesmo disfarce.

Observações: a numeração acima é minha, porque o texto extraído da página do NIST não traz números, e pode não coincidir com a do gabarito. A pergunta sobre como descobrir os nomes originais dos arquivos do RM#3 entra na 59 e não foi respondida. A página pede ainda linha do tempo, metodologia e um diagrama: são trabalho de quem examina, não foram respondidos aqui e não entram na contagem.

## Resumo antes da correção

| Marca | Quantidade |
| --- | --- |
| Direta | 25 |
| Direta só em parte (16 e 29) | 2 |
| Parcial | 12 |
| Manual | 10 |
| Não responde | 11 |
