# Teste às cegas: Compromised Windows Server 2022

Imagem pública de Benjamin Donnachie (figshare 26038642, CC BY-NC-SA 4.0), listada no portal CFReDS do NIST. O caso é simulado e não foi feito pelo NIST.

## Protocolo

- As perguntas abaixo foram escritas antes de processar a imagem e antes de ler o README que acompanha o caso.
- As respostas saem do que o programa mostra e são publicadas antes de abrir o README.
- O que se sabia antes de começar, pela página de download: é um Windows Server 2022, o cenário envolve o ransomware Red Petya e a entrada foi por acesso remoto (RDP).
- O caso não traz um gabarito de perguntas. A nota vai comparar as respostas com o que o README descreve, e o que ele não cobrir fica registrado como não conferido.

## Perguntas

1. Qual é o sistema, a versão, o nome da máquina e o fuso horário configurado?
2. Quais contas locais existem e quando cada uma entrou pela última vez?
3. Quando foi o primeiro acesso remoto do invasor?
4. De qual endereço IP ele veio?
5. Com qual conta ele entrou?
6. Houve tentativas de senha antes do acesso? Quantas, e em que período?
7. O invasor criou conta nova ou mudou grupos e privilégios?
8. Quais programas o invasor trouxe para a máquina, de onde vieram e em que pasta ficaram?
9. Quais programas ele executou, e quando?
10. Quais navegadores ou downloads foram usados?
11. Houve persistência (serviço, tarefa agendada, chave de inicialização)?
12. Algum antivírus ou registro de eventos foi desligado ou apagado?
13. Qual arquivo é o ransomware, e qual é o hash dele?
14. Quando a cifragem começou?
15. Qual mensagem de resgate ficou, e qual é o conteúdo dela?
16. O invasor tirou dados da máquina? Por qual meio?
17. Há ferramentas de descoberta de rede ou de roubo de credenciais?
18. Há conexão com outras máquinas?
19. Qual é a linha do tempo do ataque, do primeiro acesso ao fim?
20. O que indica que a imagem foi decifrada depois do ataque, como o nome do arquivo sugere?

## Como as respostas foram feitas

A leitura rodou do zero, com 172 leituras, nenhuma falha, 2h32 e 29 GB. O exame profundo não rodou, porque o disco ficou com 19 GB livres e o limite que defini era 25 GB. Sem ele, não entrou o conteúdo indexado dos arquivos.

As respostas vêm dos registros do caso e de arquivos abertos pela mesma função da tela. Consultei o banco do caso por script, o que é mais rápido do que clicar, mas os dados são os mesmos que a tela mostra. O que precisou de conta ou leitura fora disso está marcado como **manual**. Todas as horas estão em UTC, e o fuso da máquina em fevereiro coincide com UTC.

## Respostas

1. Windows Server 2022 Standard, nome `WIN-NI9FBK23SLO`, fuso `GMT Standard Time`. É controlador do domínio `branchoffice.example.com`, com a pasta `C:\share` compartilhada como `home$`.
2. **Parcial.** A leitura da SAM só traz as contas internas (Administrator, Guest, DefaultAccount, WDAGUtilityAccount), sem data de último acesso. As contas do domínio aparecem só nos eventos, com `Administrator` por último em 2024-02-09 17:12:20 e `admin` em 2024-02-09 22:52:13.
3. A primeira senha certa foi em 2024-02-05 10:55:56, um logon de rede. A primeira sessão interativa por RDP foi em 2024-02-05 23:00:28.
4. Três endereços, todos com a estação `kali`: 36.133.110.87 (senha descoberta), 185.229.66.183 (entrada por RDP em 05/02) e 31.220.85.162 (de 06/02 a 09/02). O 195.21.1.97 foi descartado: é a estação `ADMIN-WFH`, sempre das 8h às 17h, e parece ser o administrador legítimo.
5. `Administrator`, e depois a conta nova `admin`.
6. Sim. Foram 100.003 tentativas de 36.133.110.87, de 2024-02-04 23:37:28 a 2024-02-05 20:58:45, quase todas em `Administrator`. Mais 14 de 185.229.66.183, de 22:43:02 a 23:00:07 do dia 05/02.
7. Sim. `Administrator` criou `admin` ("A Admin", SID terminado em 2611) em 2024-02-05 23:02:00, trocou a senha em 23:02:01, pôs a conta em Administrators em 23:02:22 e em Domain Admins em 23:24:35. Em 2024-02-09 15:08:51, `admin` tirou `Administrator` de Domain Admins e de Group Policy Creator Owners.
8. `SysinternalsSuite.zip`, de download.sysinternals.com, em 23:13:32 do dia 05/02, e `nmap-7.93-setup.exe`, de softonic.com, em 23:41:28, ambos em `C:\Users\admin\Downloads`. Em 06/02, por volta de 20:09, `important.zip` foi para a área de trabalho e dele saíram `dir.exe` e `rename.exe`, com `RyukReadMe.txt` junto. O diário do NTFS mostra cópias em cache com `[1]` no nome, apagadas às 21:00:01. A origem provável é o FTP da pergunta 16, mas a transferência não aparece.
9. Atalhos e o cache de compatibilidade mostram `psshutdown64.exe`, `PsExec.exe`, `PsExec64.exe`, `nmap-7.93-setup.exe` e `zenmap.exe`, além de WordPad abrindo `account_password.xlsx` e `account_edit.docx` em `C:\share\Clark.Nicholson\Documents`. O Zenmap fez varreduras "Intense scan" em 2024-02-06 21:09 e 2024-02-07 10:16, com alvos `10.44.0.12/16` e `10.44.24.1/24`. Em 2024-02-09 21:46:24, a tarefa rodou o PsExec. **Limite:** o servidor não tem Prefetch, processo auditado (4688) nem Sysmon, então não há prova de execução de `dir.exe` nem data exata dos outros programas.
10. Edge, com perfil criado em 23:05:41 do dia 05/02, buscas no Bing por "download sysinternals suite" e "download nmap" e os dois downloads da pergunta 8.
11. Sim. A tarefa `\Enterpries backup` foi criada por `admin` em 2024-02-06 21:49:21, com disparo em 2024-02-09 21:46:24. A tarefa `\npcapwatchdog` e o serviço do Npcap vieram da instalação do Nmap. Nenhuma chave de inicialização suspeita apareceu.
12. O Defender foi mexido em 06/02: a chave `DisableAntiSpyware = 1` em 21:31:48 e 4 tarefas do Defender apagadas em 21:31:50, e `DisableRealtimeMonitoring = 1` em 18:59:58. **Ressalva:** essas chaves podem ter sido escritas pelo próprio sistema, e não há o comando que as mudou. Nenhum evento de registro apagado (1102 ou 104) foi encontrado.
13. `C:\Users\admin\Desktop\rename.exe`, 230.912 bytes, MD5 `af2379cc4d607a45ac44d62135fb7015`, SHA-256 `26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739`. É a carga que a tarefa manda às estações. `dir.exe` tem 806.912 bytes, MD5 `a92f13f3a1b3b39833d3cc336301b713` e SHA-256 `4c1dc737915d76b7ce579abddaba74ead6fdb5b519a1ea45308b8c49b950655c`, e sua função não foi determinada. **Manual:** os hashes foram calculados na cópia salva, e a lista de dentro de `important.zip` foi lida fora do programa. **Limite:** o programa não classifica nenhum dos dois como ransomware: as assinaturas não dispararam, e a conclusão vem do contexto. A página do caso fala em Red Petya, e a mensagem no disco assina Ryuk. Não resolvi essa diferença.
14. 2024-02-09 21:46:24, hora do disparo da tarefa `\Enterpries backup`, que roda `PsExec.exe -accept-eula \\Desktop-001,...,Desktop-006 -c -d -u admin -p letmein -realtime C:\Users\admin\Desktop\rename.exe`. É o início do lançamento nas estações. Não encontrei a cifragem em si no servidor: os arquivos de `C:\share` seguem com `.docx` e `.xlsx`.
15. `C:\Users\admin\Desktop\RyukReadMe.txt`, 1.912 bytes, aberto no Bloco de Notas em 2024-02-06 20:53:29. Diz que os arquivos foram cifrados com RSA4096 e AES-256 e cobra em bitcoin, com +0,5 BTC por dia de atraso e apagamento em 2 semanas. Contatos: `elismarco@tutanota.com` e `CamdenScott@protonmail.com`. Carteira: `15RLWdVnY5n1n7mTvU1zjg67wt86dhYqNj`.
16. Provavelmente, mas sem prova da transferência. `share.zip` esteve em `C:\Users\admin\Desktop` em 2024-02-05 23:36:06 e foi para a lixeira como `$RAN75BL.zip` em 2024-02-06 22:14:44. O invasor abriu `ftp://kali@185.239.106.67/branchoffice.example.com/` de 2024-02-06 19:54:39 a 2024-02-07 23:33:46, e o nome da pasta é o do domínio. O caso não tem captura de rede completa.
17. Descoberta: Nmap, Zenmap, ncat e nping, com resultados em `C:\Users\admin\Desktop\maps`. Credenciais: nenhuma ferramenta de roubo encontrada. Havia acesso a `account_password.xlsx`, e a senha `letmein` de `admin` aparece em texto na tarefa. A assinatura `CAPE_Risepro` em `handle.exe`, do pacote da Sysinternals, parece alarme falso.
18. Sim. `admin` usou as estações `10.44.24.1`, `.6`, `.7`, `.8` e `.9` por `\\ip\c$` e `\\ip\admin$`, digitados na barra do Explorer, com logons explícitos a partir de 2024-02-05 23:19:01. A tarefa mira Desktop-001 a Desktop-006. Desktop-006 não aparece nos eventos de segurança.
19. Linha do tempo:
    - 04/02 23:37: começa a tentativa de senhas de 36.133.110.87.
    - 05/02 10:55:56: primeira senha certa em `Administrator`.
    - 05/02 22:43 a 23:00: 185.229.66.183 tenta, entra por rede em 22:55:18 e por RDP em 23:00:28.
    - 05/02 23:02: cria `admin`, e em 23:24 põe em Domain Admins.
    - 05/02 23:04 a 23:09: percorre `C:\share` e abre `account_password.xlsx`.
    - 05/02 23:13 e 23:41: baixa Sysinternals e Nmap.
    - 05/02 23:36: `share.zip`.
    - 06/02 19:52: volta por 31.220.85.162.
    - 06/02 19:54: abre o FTP.
    - 06/02 20:09: `important.zip`.
    - 06/02 21:09: varredura.
    - 06/02 21:31: mudanças no Defender.
    - 06/02 21:49: cria a tarefa.
    - 09/02 15:08: tira `Administrator` de Domain Admins.
    - 09/02 21:46:24: a tarefa dispara o PsExec.
    - 09/02 22:52:13: último acesso de `admin`.
    - 09/02 22:56: últimos registros.
20. **Sem resposta.** Só o nome do arquivo indica isso. Nenhum registro mostra cifragem nem decifragem do disco, e o programa não examina esse tipo de dano.

## Falhas que o teste já mostrou

Estas apareceram antes de abrir o README:

- A análise levou 2h32, contra 30 minutos no Data Leakage. Falta medir qual etapa pesa mais; o caso tem 3 milhões de registros.
- As datas dos eventos de rede vindos de `packets.pcap` ficam vazias, e as conexões saem com "( bytes enviados, recebidos)" sem os números.
- Nada liga sozinho o que o invasor fez em um resumo: a história acima foi montada por mim.
- As chaves do registro aparecem como `Services: None` e `File Extensions: Multiple`, sem dizer o que é relevante.
- O histórico do navegador só tem a conta `admin` até 05/02 23:41, sem nada do que veio depois.
- `RyukReadMe.txt` e `important.zip` têm data de criação (07/02 04:46 e 04:04) posterior à de mudança (06/02 20:53 e 20:09). O programa não avisa dessa inversão.
