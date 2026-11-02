#!/usr/bin/env python3
# Le as copias de sombra de uma imagem de disco, sem montar nada e sem copiar a imagem.
# Responde no contrato de modulos: registros.jsonl e derivados.jsonl.
# Uso: sombra.py <pasta de saida> <primeiro segmento da imagem>
from collections import OrderedDict
import json
import os
import re
import sqlite3
import sys

import pyewf
import pytsk3
import pyvshadow

# Arquivos pequenos das copias que valem voltar ao caso como nova evidencia.
ARTEFATOS = re.compile(
    r"(?i)(/google/drive/user_default/(sync_log\.log|snapshot\.db|sync_config\.db)"
    r"|/users/[^/]+/ntuser\.dat|/users/[^/]+/.*/usrclass\.dat"
    r"|/recent/[^/]+\.lnk|/automaticdestinations/[^/]+-ms)$"
)
LIMITE_ARTEFATO = 64 * 1024 * 1024
SETOR = 512
BLOCO = 64 * 1024
BLOCOS_NO_CACHE = 4096
# Pastas do sistema ficam fora: sao a maior parte do disco e repetem o que o sistema instala.
FORA = re.compile(r"(?i)^/(windows|program files[^/]*|\$[^/]*|system volume information|msocache)$")


class ImagemEWF:
    """Conteudo de um E01, por dentro. Tambem aceita imagem bruta."""

    def __init__(self, caminho):
        if caminho.lower().endswith(".e01"):
            segmentos = pyewf.glob(caminho)
            self.h = pyewf.handle()
            self.h.open(segmentos)
        else:
            self.h = open(caminho, "rb")
        self.h.seek(0, os.SEEK_END)
        self.tamanho = self.h.tell()
        self.h.seek(0)
        self.cache = OrderedDict()

    def bloco(self, numero):
        # As bibliotecas leem setor a setor, e cada leitura no E01 descomprime um trecho.
        dados = self.cache.get(numero)
        if dados is None:
            self.h.seek(numero * BLOCO)
            dados = self.h.read(BLOCO)
            self.cache[numero] = dados
            if len(self.cache) > BLOCOS_NO_CACHE:
                self.cache.popitem(last=False)
        else:
            self.cache.move_to_end(numero)
        return dados

    def ler(self, posicao, n):
        partes = []
        while n > 0:
            numero, dentro = divmod(posicao, BLOCO)
            pedaco = self.bloco(numero)[dentro:dentro + n]
            if not pedaco:
                break
            partes.append(pedaco)
            posicao += len(pedaco)
            n -= len(pedaco)
        return b"".join(partes)


class Trecho:
    """Janela de uma imagem, no formato de arquivo que a biblioteca espera."""

    def __init__(self, imagem, inicio):
        self.imagem, self.inicio, self.pos = imagem, inicio, 0

    def read(self, n=None):
        limite = self.get_size() - self.pos
        n = limite if n is None else min(n, limite)
        dados = self.imagem.ler(self.inicio + self.pos, n) if n > 0 else b""
        self.pos += len(dados)
        return dados

    def seek(self, posicao, origem=os.SEEK_SET):
        self.pos = {os.SEEK_SET: 0, os.SEEK_CUR: self.pos, os.SEEK_END: self.get_size()}[origem] + posicao

    def tell(self):
        return self.pos

    def get_size(self):
        return self.imagem.tamanho - self.inicio

    def get_offset(self):
        return self.pos


class ImgImagem(pytsk3.Img_Info):
    def __init__(self, imagem):
        self.imagem = imagem
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def read(self, posicao, n):
        return self.imagem.ler(posicao, n)

    def get_size(self):
        return self.imagem.tamanho

    def close(self):
        pass


class ImgStore(pytsk3.Img_Info):
    def __init__(self, store):
        self.store = store
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def read(self, posicao, n):
        return self.store.read_buffer_at_offset(n, posicao)

    def get_size(self):
        return self.store.get_size()

    def close(self):
        pass


def particoes(imagem):
    try:
        volume = pytsk3.Volume_Info(ImgImagem(imagem))
    except OSError:
        return [0]
    return [p.start for p in volume if p.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC and p.len > 2048]


def percorrer(fs, pasta="/", vistos=None):
    """Lista os arquivos com tamanho e datas, sem repetir pasta, inclusive os apagados."""
    vistos = set() if vistos is None else vistos
    try:
        diretorio = fs.open_dir(path=pasta)
    except OSError:
        return
    for entrada in diretorio:
        nome = entrada.info.name.name
        if nome in (b".", b"..") or entrada.info.meta is None:
            continue
        nome = nome.decode("utf-8", "replace")
        caminho = pasta.rstrip("/") + "/" + nome
        meta = entrada.info.meta
        eh_pasta = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
        ativo = bool(entrada.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_ALLOC)
        yield caminho, entrada, meta, eh_pasta, ativo
        if eh_pasta and ativo and meta.addr not in vistos and not FORA.match(caminho):
            vistos.add(meta.addr)
            yield from percorrer(fs, caminho, vistos)


def data(segundos):
    from datetime import datetime, timezone

    if not segundos or segundos <= 0:
        return ""
    return datetime.fromtimestamp(segundos, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def conteudo(entrada, tamanho):
    partes, lido = [], 0
    while lido < tamanho:
        bloco = entrada.read_random(lido, min(1024 * 1024, tamanho - lido))
        if not bloco:
            break
        partes.append(bloco)
        lido += len(bloco)
    return b"".join(partes)


IDENTIFICADOR = re.compile(rb"0B[0-9A-Za-z_-]{26}")
COLUNAS = ("doc_id", "filename", "modified", "created", "acl_role", "doc_type", "removed", "size", "checksum", "shared", "resource_type")
TAMANHO_INTEIRO = {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8}


def varint(dados, i):
    valor = 0
    for _ in range(9):
        byte = dados[i]
        i += 1
        valor = (valor << 7) | (byte & 0x7f)
        if byte < 0x80:
            break
    return valor, i


def valores_cloud(dados, posicao, tipos):
    linha, i = {}, posicao
    for coluna, tipo in zip(COLUNAS, tipos):
        if tipo in TAMANHO_INTEIRO:
            n = TAMANHO_INTEIRO[tipo]
            linha[coluna] = int.from_bytes(dados[i:i + n], "big", signed=True)
            i += n
        elif tipo >= 13 and tipo % 2:
            n = (tipo - 13) // 2
            linha[coluna] = dados[i:i + n].decode("ascii")
            i += n
        elif tipo in (8, 9):
            linha[coluna] = tipo - 8
        elif tipo == 0:
            linha[coluna] = None
        else:
            raise ValueError(tipo)
    return linha


def registro_cloud(dados, posicao):
    """Interpreta uma linha de cloud_entry a partir do identificador, a primeira coluna. Uma
    linha apagada pode perder os primeiros bytes, inclusive o tipo do identificador, mas os
    tipos das outras colunas continuam logo antes dele. Por isso eles sao lidos sozinhos, e o
    identificador tem sempre 28 caracteres (tipo 69)."""
    for recuo in range(10, 15):
        i = posicao - recuo
        if i < 0:
            continue
        try:
            tipos = [69]
            while len(tipos) < len(COLUNAS):
                tipo, i = varint(dados, i)
                tipos.append(tipo)
            if i != posicao:
                continue
            linha = valores_cloud(dados, posicao, tipos)
        except (IndexError, ValueError):
            continue
        # A soma do arquivo confirma que os tipos foram lidos no lugar certo.
        if linha.get("filename") and re.fullmatch(r"[0-9a-f]{32}", str(linha.get("checksum"))):
            return linha
    return None


def linhas_de_snapshot(dados):
    """Le as linhas de cloud_entry direto nos bytes do banco, inclusive as apagadas, que ficam
    nas paginas livres ate serem reaproveitadas."""
    vistos = {}
    for m in IDENTIFICADOR.finditer(dados):
        linha = registro_cloud(dados, m.start())
        if linha and linha.get("filename"):
            vistos.setdefault(linha["doc_id"], (m.start(), linha))
    return vistos


def ativos_de_snapshot(caminho):
    try:
        banco = sqlite3.connect("file:%s?mode=ro&immutable=1" % caminho, uri=True)
        ativos = {linha[0] for linha in banco.execute("SELECT doc_id FROM cloud_entry")}
        banco.close()
        return ativos
    except sqlite3.Error:
        return None


def main():
    saida, arquivo = sys.argv[1], sys.argv[2]
    imagem = ImagemEWF(arquivo)
    nome_imagem = os.path.basename(arquivo)
    registros = open(os.path.join(saida, "registros.jsonl"), "w", encoding="utf-8")
    derivados = open(os.path.join(saida, "derivados.jsonl"), "w", encoding="utf-8")
    numero_extraido = 0

    def registro(**campos):
        campos.setdefault("tipo", "evento")
        campos.setdefault("fonte", "Cópia de sombra")
        registros.write(json.dumps(campos, ensure_ascii=False) + "\n")

    for inicio in particoes(imagem):
        volume_bytes = inicio * SETOR
        trecho = Trecho(imagem, volume_bytes)
        sombra = pyvshadow.volume()
        try:
            sombra.open_file_object(trecho)
        except OSError:
            continue
        total = sombra.get_number_of_stores()
        if total == 0:
            continue
        atual = {}
        fs_atual = pytsk3.FS_Info(ImgImagem(imagem), offset=volume_bytes)
        for caminho, _, meta, eh_pasta, ativo in percorrer(fs_atual):
            if ativo and not eh_pasta:
                atual[caminho.lower()] = (meta.size, meta.mtime)
        for indice in range(total):
            store = sombra.get_store(indice)
            criada = store.get_creation_time().strftime("%Y-%m-%dT%H:%M:%SZ")
            rotulo = "cópia %d" % (indice + 1)
            local = "%s, setor %d, %s" % (nome_imagem, inicio, rotulo)
            registro(
                quando=criada, descricao="Cópia de sombra criada: %s, partição no setor %d, %d bytes" % (rotulo, inicio, store.get_size()),
                origem_local=local,
                dados={"imagem": nome_imagem, "particao": inicio, "copia": indice + 1, "identificador": store.get_identifier(), "conjunto": store.get_copy_set_identifier(), "criada": criada},
            )
            fs = pytsk3.FS_Info(ImgStore(store))
            ausentes = alterados = iguais = 0
            for caminho, entrada, meta, eh_pasta, ativo in percorrer(fs):
                if eh_pasta or not ativo or meta.size is None:
                    continue
                agora = atual.get(caminho.lower())
                artefato = bool(ARTEFATOS.search(caminho)) and 0 < meta.size <= LIMITE_ARTEFATO
                diferenca = ""
                if agora is None:
                    ausentes += 1
                    diferenca = "só na cópia"
                elif agora != (meta.size, meta.mtime):
                    alterados += 1
                    diferenca = "diferente do disco atual"
                else:
                    iguais += 1
                # So o que nao esta igual no disco: o resto repetiria a leitura normal.
                if not diferenca or caminho.lower().startswith("/programdata/microsoft/"):
                    continue
                registro(
                    quando=data(meta.mtime),
                    descricao="%s na %s (%s): %s" % ("Arquivo", rotulo, diferenca, caminho),
                    origem_local=local,
                    entidades=[{"tipo": "arquivo", "valor": caminho.rsplit("/", 1)[-1]}],
                    dados={"caminho": caminho, "tamanho": meta.size, "copia": indice + 1, "alterado": data(meta.mtime), "criado": data(meta.crtime), "situacao": diferenca},
                )
                if not artefato:
                    continue
                dados = conteudo(entrada, meta.size)
                numero_extraido += 1
                relativo = "derivados/%d" % numero_extraido
                destino = os.path.join(saida, relativo)
                os.makedirs(os.path.dirname(destino), exist_ok=True)
                with open(destino, "wb") as f:
                    f.write(dados)
                derivados.write(json.dumps({
                    "arquivo": relativo, "nome": caminho.rsplit("/", 1)[-1],
                    "origem": "%s!%s%s" % (nome_imagem, rotulo, caminho), "evidencia": sys.argv[3],
                }) + "\n")
                if caminho.lower().endswith("sync_log.log"):
                    registro(
                        quando=data(meta.mtime), fonte="Conteúdo de arquivo",
                        descricao="Texto do arquivo na %s: %s" % (rotulo, caminho), origem_local=local,
                        dados={"caminho": caminho, "texto": dados.decode("utf-8", "replace")},
                    )
                if caminho.lower().endswith("snapshot.db"):
                    ativos = ativos_de_snapshot(destino)
                    for doc, (posicao, linha) in sorted(linhas_de_snapshot(dados).items(), key=lambda x: x[1][0]):
                        situacao = "registro apagado" if ativos is not None and doc not in ativos else "registro ativo"
                        registro(
                            quando=data(linha.get("modified")), fonte="Google Drive na cópia de sombra",
                            descricao="%s no banco do Google Drive: %s, %s bytes, hash %s" % (situacao.capitalize(), linha["filename"], linha.get("size"), linha.get("checksum")),
                            origem_local="%s, posição %d de snapshot.db" % (local, posicao),
                            entidades=[{"tipo": "arquivo", "valor": linha["filename"]}],
                            dados=dict(linha, situacao=situacao, posicao=posicao, copia=indice + 1, modificado=data(linha.get("modified")), criado=data(linha.get("created"))),
                        )
            registro(
                quando=criada,
                descricao="Comparação da %s com o disco atual, sem as pastas do sistema: %d arquivos iguais, %d diferentes, %d só na cópia" % (rotulo, iguais, alterados, ausentes),
                origem_local=local,
                dados={"iguais": iguais, "diferentes": alterados, "so_na_copia": ausentes, "copia": indice + 1},
            )
    registros.close()
    derivados.close()


if __name__ == "__main__":
    main()
