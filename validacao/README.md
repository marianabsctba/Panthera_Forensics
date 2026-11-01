# Validação

Compara o resultado do Panthera Forensics com dados de referência públicos do NIST (CFReDS). O NIST não certifica ferramentas: isto é um teste nosso, usando os dados e o gabarito deles.

```bash
PANTHERA_HOME=<pasta com ferramentas> PANTHERA_DADOS=<pasta de dados> go test -tags validacao -v -count=1 ./validacao
```

## Resultados

| Caso | O que confere | Situação |
|---|---|---|
| DFR-01 NTFS | Arquivo apagado, tamanho, datas de alteração, acesso e mudança, arquivos ativos | Passa |
| DFR-16 NTFS | Todos os nomes de arquivo ativos do gabarito aparecem como ativos | Passa |

| Memória boomer-win2003 | Processos documentados pelo NIST, como o Notepad | **Não passa**: o sistema e a versão são reconhecidos, mas `windows.pslist` traz duas linhas vazias e `windows.psscan` não traz nada |

Com isso, os módulos de memória não estão validados. Essas imagens são de 2005 e 2006, então falta testar com uma imagem de Windows moderno que tenha conteúdo documentado.

## Limites desta validação

- A `$MFT` foi extraída da imagem por um script auxiliar, fora do produto. Ler a imagem de disco direto ainda não faz parte do fluxo, então esse trecho não foi validado.
- Só valida o módulo da tabela de arquivos no fluxo completo. Recuperar conteúdo apagado, carving, Registro do Windows, busca de strings e imageamento não foram testados.
- O DFR-16 confere que nada do gabarito falta. Ele não confere se há arquivos a mais.
- O gabarito do DFR-16 é lido do PDF convertido em texto e reconhece só os nomes no padrão `4-NN-NNNNN.txt`.
- A MFT não registra a hora da exclusão. No DFR-01, a última mudança do registro é 12 minutos anterior à exclusão real, e a timeline informa isso como momento desconhecido.

## Dados

Em `PANTHERA_DADOS/nist-dfr`:

- `setup.txt`: [documento de layout](https://cfreds-archive.nist.gov/dfr-images/setup-july-10-2012.pdf), convertido com `pdftotext -layout`.
- `mft-01/p61/$MFT`: `$MFT` da partição iniciada no setor 61 de [dfr-01-ntfs.dd.bz2](https://cfreds-archive.nist.gov/dfr-images/dfr-01-ntfs.dd.bz2).
- `mft-16/p128/$MFT`: `$MFT` da partição iniciada no setor 128 de [dfr-16-ntfs.dd.bz2](https://cfreds-archive.nist.gov/dfr-images/dfr-16-ntfs.dd.bz2).
