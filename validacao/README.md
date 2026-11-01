# Validação

Compara o resultado do Panthera Forensics com dados de referência públicos do NIST (CFReDS) e, nos navegadores, com amostras do projeto Hindsight. O NIST não certifica ferramentas: isto é um teste nosso, usando os dados e o gabarito deles.

```bash
PANTHERA_HOME=<pasta com ferramentas> PANTHERA_DADOS=<pasta de dados> go test -tags validacao -v -count=1 -timeout 30m ./validacao
```

## Resultados

| Caso | O que confere | Situação |
|---|---|---|
| DFR-01 NTFS, da imagem e da `$MFT` | Arquivo apagado, tamanho, datas e arquivos ativos | Passa |
| DFR-16 NTFS, da imagem e da `$MFT` | Todos os nomes de arquivo ativos do gabarito aparecem | Passa |
| Hacking Case | 20 das 31 perguntas, listadas abaixo | Passa nas 20; Q30 diverge; as demais não foram testadas |
| Navegadores (amostras do Hindsight) | Chrome com 63 itens, Firefox com 6, sem perda | Passa |
| Rede (amostra do projeto Suricata) | Regra 2100498 esperada, fuso convertido, conexão registrada | Passa |
| Logs do Windows com Chainsaw (amostra pública) | Alerta crítico em um log que foi limpo | Passa |
| Arquivo limpo (`notepad.exe`) | Sem alerta de assinatura; capacidades descritas | Passa |
| Nome de arquivo malicioso | Nenhum comando executado; captura cortada marcada como parcial | Passa |
| Memória boomer-win2003 | Processos documentados pelo NIST, como o Notepad | **Não passa** |

### Hacking Case

- **Passam:** Q1 hash, Q2 sistema, Q3 instalação, Q4 fuso, Q5 dono, Q6 computador, Q8 desligamento, Q9 contas, Q11 último usuário, Q12 arquivo do Look@LAN, Q14 IP, Q16 programas, Q17 e-mail SMTP, Q22 canais de IRC, Q23 arquivo interceptado, Q24 sistema da vítima, Q25 site acessado, Q26 e-mail web, Q27 cópia de e-mail e Q28 executáveis na lixeira.
- **Diverge:** na Q30, o gabarito diz 3 arquivos apagados, e o The Sleuth Kit lista 70 entradas apagadas com metadados. A causa não foi confirmada, e o número não foi ajustado.
- **Não testadas:** Q7, Q10, Q13, Q15, Q18 a Q21, Q29 e Q31.
- **Alcance:** Q12, Q14, Q16, Q17, Q22 a Q27 confirmam que a informação existe no caso e que a busca a encontra. Como o teste já sabe o que procurar, isso não demonstra que um exame sem o gabarito chegaria a ela.
- **Calibração:** as regras próprias de uso duplo foram ajustadas vendo este caso. Não houve alarme falso em nenhum `.exe` ou `.dll` da pasta `System32` desta máquina (sem subpastas), mas a taxa de acerto em casos desconhecidos não foi medida.

### Memória

O Volatility reconhece o sistema e a versão, mas `windows.pslist` traz duas linhas vazias e `windows.psscan` não traz nada. Os módulos de memória não estão validados. Essas imagens são de 2005 e 2006, então falta testar com uma imagem de Windows moderno que tenha conteúdo documentado.

### Navegadores

O JSONL do Hindsight 2026.06 perde visitas e downloads do Firefox, mesmo informando o total certo. O módulo usa a saída SQLite, que traz tudo, mas com datas em milissegundos em vez de microssegundos.

## Limites desta validação

- Recuperar o conteúdo de arquivos apagados, carving, busca de strings e imageamento não foram testados.
- O teste de Registro confere valores do Hacking Case, não o conjunto `cfreds-2017-winreg`.
- Os casos DFR conferem que nada do gabarito falta. O DFR-16 não confere se há arquivos a mais.
- O gabarito do DFR-16 é lido do PDF convertido em texto e reconhece só os nomes no padrão `4-NN-NNNNN.txt`.
- Na leitura de disco, as datas têm precisão de segundos. A leitura direta da `$MFT` é mais precisa.
- O sistema de arquivos não registra a hora da exclusão. No DFR-01, a última mudança é 12 minutos anterior à exclusão real, e a timeline informa isso como momento desconhecido.

## Dados

Em `PANTHERA_DADOS`:

- `nist-dfr/setup.txt`: [documento de layout](https://cfreds-archive.nist.gov/dfr-images/setup-july-10-2012.pdf), convertido com `pdftotext -layout`.
- `nist-dfr/dfr-01-ntfs.dd` e `nist-dfr/dfr-16-ntfs.dd`: [imagem 01](https://cfreds-archive.nist.gov/dfr-images/dfr-01-ntfs.dd.bz2) e [imagem 16](https://cfreds-archive.nist.gov/dfr-images/dfr-16-ntfs.dd.bz2), descomprimidas.
- `nist-dfr/mft-01/p61/$MFT` e `nist-dfr/mft-16/p128/$MFT`: `$MFT` extraída dessas imagens por um script auxiliar.
- `hacking/4Dell Latitude CPi.E01` e `.E02`: [Hacking Case](https://cfreds-archive.nist.gov/Hacking_Case.html).
- `pcap/testmyids.pcap`: `tests/alert-testmyids-async/input.pcap` do [suricata-verify](https://github.com/OISF/suricata-verify).
- `pcap/hacking-packets.pcap`: pacotes que o bulk_extractor encontra no disco do Hacking Case.
- `hayabusa-sample-evtx`: clone de [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx).
- `hindsight/chrome/History` e `hindsight/firefox/places.sqlite`: `tests/fixtures/profiles/60/History` e `tests/fixtures/firefox/places.sqlite` do [Hindsight](https://github.com/obsidianforensics/hindsight).
