# Panthera Forensics

Suíte forense local: abrir o executável, arrastar a evidência e investigar. O núcleo em Go cuida de caso, custódia, timeline, interface e relatório. As ferramentas open source entram como módulos, e o núcleo não conhece nenhuma delas.

## Estado atual

| Parte | Situação |
|---|---|
| Caso, cofre de evidências, custódia encadeada | Pronto, com testes |
| Contrato de módulos, plano automático, reaproveitamento | Pronto, com testes usando uma ferramenta de teste |
| Interface local e relatório | Prontos, conferidos no navegador com dados de demonstração |
| Instalador com hash fixado | Pronto, com testes |
| Leitura de imagem de disco (The Sleuth Kit), `.dd` e `.E01` segmentado | Testada com dados de referência do NIST, ver [validação](validacao/README.md) |
| Módulos MFTECmd e RECmd (Registro) | Testados com dados de referência do NIST |
| Módulo Hindsight (Chrome e Firefox) | Testado com amostras do próprio projeto Hindsight |
| Módulos Hayabusa, EvtxECmd e PECmd | Executados com amostras públicas reais, sem gabarito formal |
| Módulos de memória (Volatility) | **Não validados**: não listam processos nas imagens do NIST, de 2005 e 2006 |
| Módulos bulk_extractor, YARA, capa, Chainsaw, tshark, Zeek, Suricata e Plaso | Executados com dados públicos reais, ver [validação](validacao/README.md) |
| Ambiente Linux dedicado (WSL) para tshark, Zeek, Suricata e Plaso | Instalado e em uso; a criação pelo `preparar` a partir do zero ainda não foi testada |
| Exame profundo opcional (IPED) | DFR-01 confere com o gabarito; e-mails, histórico do Internet Explorer e busca do Windows conferidos no Data Leakage |
| Linha do tempo completa opcional (Plaso) | Separada do exame profundo por poder levar horas; só tem conferência de datas |
| Atalhos, listas de atalhos, pastas navegadas, lixeira e diário do NTFS | Conferidos com o gabarito do Data Leakage |
| Cópias de sombra | Conferidas com o gabarito do Data Leakage, que só tem uma cópia e em Windows 7 |
| CD e DVD em UDF | Leitura própria por assinatura; conferida em um único caso, o CD-R do Data Leakage |
| Visão geral, gráficos, filtros, mapa de conexões, marcações e fuso da evidência | Prontos, conferidos no navegador com o Hacking Case |
| Busca no conteúdo | Arquivos de texto de até 2 MB fora da pasta do Windows na análise padrão; demais formatos no exame profundo, sem janela de outro programa |
| Recuperação do conteúdo de arquivos apagados | Pela tela do programa; 17 arquivos da RM#2 do Data Leakage com o tamanho do gabarito |
| Teste às cegas com um caso não usado para calibrar | Data Leakage: 20 de 57 sem ajuda. Depois de corrigir, 52 de 57, já sem valor de teste às cegas ([nota](validacao/data-leakage-nota.md)) |
| Coletor para a máquina-alvo | Não feito |

## Antivírus

Resultados de ferramentas citam trechos de ataques reais, e evidências podem conter malware. O Windows Defender já bloqueou um resultado do Hayabusa durante os testes e pode colocar evidência em quarentena. Guarde os casos em uma pasta dedicada, excluída do antivírus. A conferência de integridade acusa evidência que sumiu ou mudou.

## Uso

```bash
go build -ldflags -H=windowsgui -o panthera-forensics.exe ./cmd/panthera-forensics
```

Dois cliques no executável abrem a interface em `127.0.0.1`, sem nenhuma janela de console, e o botão **Encerrar** fecha o programa. Casos, ferramentas e módulos locais ficam ao lado dele, ou na pasta indicada em `PANTHERA_HOME`. Use um disco com espaço, porque as evidências são copiadas para o caso.

Comandos, para quem quiser automatizar:

```text
panthera-forensics preparar                         baixa as ferramentas e confere o hash
panthera-forensics modulos                          lista os módulos
panthera-forensics novo [-numero N] [-perito P] X   cria um caso
panthera-forensics processar <caso> <caminho>...    preserva e lê as evidências
panthera-forensics aprofundar <caso>                roda o exame profundo, mais pesado
panthera-forensics verificar <caso>                 recalcula os hashes
panthera-forensics relatorio <caso>                 grava o relatório
```

## Módulos

Um módulo é uma pasta `modulos/<nome>/modulo.yaml`, ao lado do executável ou embutida nele. Para plugar uma ferramenta, não é preciso mexer no núcleo:

```yaml
contrato: 1
nome: exemplo
titulo: Texto que aparece na tela
versao: "1.0"
reconhece:                     # ensina a identificar o tipo de evidência
  - tipo: meu-formato
    magica_hex: "4142"         # a assinatura vale mais que o nome
    extensoes: [.abc]
consome: [meu-formato]
modo: arquivo                  # ou lote, para receber uma pasta
instalar:                      # opcional; sem isso, o executável fica na pasta do módulo
  windows-amd64: {url: "https://...", sha256: "..."}
comando:
  windows:
    exec: ferramenta*.exe      # aceita curinga
    args: ["{entrada}", "{saida}"]
    # dir: ferramenta          roda na pasta da ferramenta
    # stdout: saida.jsonl      grava a saída padrão em um arquivo
saida:
  arquivos: "*.csv"
  formato: csv                 # csv, jsonl ou contrato
  severidades: {crit: critica}
  mapas:
    - tipo: alerta             # alerta aparece em "O que merece atenção"
      quando: "{Hora}"
      descricao: "{Regra}"
      severidade: "{Nivel}"
      origem_local: "{Linha}"
      entidades:
        - {tipo: host, valor: "{Maquina}"}
```

No formato `contrato`, a ferramenta já escreve um JSON por linha com os campos de `normaliza.Registro` e dispensa os mapas.

## Garantias e limites

- A evidência é copiada para um cofre pelo próprio SHA-256, com SHA-1 e MD5 calculados na cópia, e fica somente leitura. As ferramentas recebem um link para esse arquivo.
- Cada passo entra em um registro em que cada linha guarda o hash da anterior. A remoção das últimas linhas só é detectada comparando com o hash final impresso no relatório, que deve ser guardado fora do caso.
- A saída bruta de cada ferramenta fica preservada em `execucoes/`. Módulo ausente ou com falha fica registrado e aparece no relatório.
- Todo conteúdo vindo da evidência é tratado como hostil na interface e no relatório.
- A interface escuta só em `127.0.0.1`, recusa outro `Host` e exige token para alterar estado.
- Pacotes `.zip` são abertos automaticamente, ainda sem limite contra pacote malicioso que se expande demais. Abra evidência suspeita em um disco dedicado.
- Achados são pistas automáticas e precisam ser conferidos na evidência de origem.
- A validação deverá seguir os métodos e dados de referência do NIST (CFTT e CFReDS). O NIST não certifica ferramentas, então isso não é uma aprovação do NIST.

## Desenvolvimento

```bash
go test ./...
```
