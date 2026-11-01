package disco

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// A leitura de disco nao abre UDF, o formato de CD e DVD gravados como pendrive. Sem isso,
// um disco com arquivos apagados de proposito ficaria sem leitura nenhuma. O caminho aqui
// nao depende da estrutura estar integra: procura as entradas de diretorio pela assinatura,
// inclusive as apagadas, e recupera documentos pelo conteudo.

const blocoVarredura = 64 * 1024 * 1024

// EhUDF procura os descritores que abrem um volume UDF, a partir de 32 KB do inicio.
func EhUDF(inicio []byte) bool {
	if len(inicio) < 32770 {
		return false
	}
	resto := inicio[32768:]
	return bytes.Contains(resto, []byte("BEA01")) &&
		(bytes.Contains(resto, []byte("NSR02")) || bytes.Contains(resto, []byte("NSR03")))
}

// EntradaUDF e uma entrada de diretorio encontrada na imagem.
type EntradaUDF struct {
	Posicao int64
	Nome    string
	Apagada bool
	Pasta   bool
}

// InterpretarEntradasUDF acha os File Identifier Descriptors de um trecho, conferindo a soma
// de verificacao de cada um. Uma entrada apagada perde so a primeira letra do nome.
func InterpretarEntradasUDF(b []byte, deslocamento int64) []EntradaUDF {
	var saida []EntradaUDF
	for i := 0; i+40 <= len(b); i += 4 {
		if b[i] != 1 || b[i+1] != 1 {
			continue
		}
		var soma byte
		for j := 0; j < 16; j++ {
			if j != 4 {
				soma += b[i+j]
			}
		}
		if soma != b[i+4] {
			continue
		}
		caracteristicas, tamanhoNome := b[i+18], int(b[i+19])
		uso := int(binary.LittleEndian.Uint16(b[i+36:]))
		if caracteristicas&8 != 0 || tamanhoNome == 0 || i+38+uso+tamanhoNome > len(b) {
			continue
		}
		nome := nomeUDF(b[i+38+uso : i+38+uso+tamanhoNome])
		if nome == "" {
			continue
		}
		saida = append(saida, EntradaUDF{
			Posicao: deslocamento + int64(i), Nome: nome,
			Apagada: caracteristicas&4 != 0, Pasta: caracteristicas&2 != 0,
		})
	}
	return saida
}

func nomeUDF(n []byte) string {
	switch n[0] {
	case 8:
		return string(n[1:])
	case 16:
		unidades := make([]uint16, 0, len(n)/2)
		for i := 1; i+1 < len(n); i += 2 {
			unidades = append(unidades, binary.BigEndian.Uint16(n[i:]))
		}
		return string(utf16.Decode(unidades))
	case 254, 255:
		// A entrada apagada troca o identificador de compressao por este marcador.
		return "?" + string(n[1:])
	}
	return ""
}

// Recuperado e um documento achado pelo conteudo, com o que ajuda a identificar o original.
type Recuperado struct {
	Posicao, Tamanho        int64
	Extensao, Titulo        string
	Criado, Alterado, Texto string
}

var (
	marcaZip    = []byte("PK\x03\x04")
	fimZip      = []byte("PK\x05\x06")
	marcaOLE    = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}
	etiquetaXML = regexp.MustCompile(`<[^>]+>`)
	espacos     = regexp.MustCompile(`\s+`)
)

// CarregarDocumentos procura documentos do Office em uma imagem, sem olhar dentro do que ja
// foi reconhecido, para nao contar as partes de um documento como arquivos soltos.
func CarregarDocumentos(f io.ReaderAt, tamanho int64) ([]Recuperado, error) {
	var achados []Recuperado
	var fimDoUltimo int64
	buffer := make([]byte, blocoVarredura)
	// Blocos sem sobreposicao: as assinaturas so sao procuradas no inicio de cada setor.
	for inicio := int64(0); inicio < tamanho; inicio += blocoVarredura {
		n, err := f.ReadAt(buffer, inicio)
		if err != nil && err != io.EOF {
			return achados, err
		}
		trecho := buffer[:n]
		for _, p := range posicoes(trecho) {
			posicao := inicio + p
			if posicao < fimDoUltimo {
				continue
			}
			var r *Recuperado
			if bytes.HasPrefix(trecho[p:], marcaZip) {
				r = documentoZip(f, posicao, tamanho)
			} else {
				r = documentoOLE(f, posicao, tamanho)
			}
			if r != nil {
				achados = append(achados, *r)
				fimDoUltimo = r.Posicao + r.Tamanho
			}
		}
		if n < blocoVarredura {
			break
		}
	}
	return achados, nil
}

// posicoes lista, em ordem, onde um zip ou um documento antigo do Office pode comecar.
// Os dois comecam no inicio de um setor quando sao gravados como arquivo.
func posicoes(b []byte) []int64 {
	var p []int64
	for i := 0; i+8 <= len(b); i += 2048 {
		if bytes.HasPrefix(b[i:], marcaZip) || bytes.HasPrefix(b[i:], marcaOLE) {
			p = append(p, int64(i))
		}
	}
	return p
}

func documentoZip(f io.ReaderAt, posicao, tamanho int64) *Recuperado {
	limite := min(tamanho-posicao, 2*1024*1024*1024)
	trecho := io.NewSectionReader(f, posicao, limite)
	buffer := make([]byte, blocoVarredura)
	var lido int64
	// Um zip pode guardar outro zip: o fim certo e o primeiro que deixa o arquivo abrir.
	for tentativas := 0; lido < limite && tentativas < 2048; {
		n, err := trecho.ReadAt(buffer, lido)
		if n < len(fimZip)+20 {
			return nil
		}
		for i := 0; i+22 <= n; {
			q := bytes.Index(buffer[i:n], fimZip)
			if q < 0 {
				break
			}
			i += q
			if i+22 > n {
				break
			}
			comentario := int64(binary.LittleEndian.Uint16(buffer[i+20:]))
			total := lido + int64(i) + 22 + comentario
			tentativas++
			if leitor, erro := zip.NewReader(io.NewSectionReader(f, posicao, total), total); erro == nil && len(leitor.File) > 0 {
				return resumirZip(leitor, posicao, total)
			}
			i += 4
		}
		if err != nil {
			return nil
		}
		lido += int64(n) - 21
	}
	return nil
}

func resumirZip(z *zip.Reader, posicao, total int64) *Recuperado {
	r := &Recuperado{Posicao: posicao, Tamanho: total, Extensao: ".zip"}
	principal := ""
	for _, a := range z.File {
		switch {
		case a.Name == "word/document.xml":
			r.Extensao, principal = ".docx", a.Name
		case a.Name == "ppt/slides/slide1.xml":
			r.Extensao, principal = ".pptx", a.Name
		case a.Name == "xl/sharedStrings.xml":
			r.Extensao, principal = ".xlsx", a.Name
		case a.Name == "xl/workbook.xml" && r.Extensao == ".zip":
			r.Extensao = ".xlsx"
		case a.Name == "docProps/core.xml":
			nucleo := textoDoZip(a, 64*1024)
			r.Titulo = campoXML(nucleo, "dc:title")
			r.Criado = campoXML(nucleo, "dcterms:created")
			r.Alterado = campoXML(nucleo, "dcterms:modified")
		}
	}
	for _, a := range z.File {
		if a.Name == principal {
			r.Texto = resumir(etiquetaXML.ReplaceAllString(textoDoZip(a, 256*1024), " "))
		}
	}
	return r
}

func textoDoZip(a *zip.File, limite int64) string {
	leitor, err := a.Open()
	if err != nil {
		return ""
	}
	defer leitor.Close()
	dados, _ := io.ReadAll(io.LimitReader(leitor, limite))
	return string(dados)
}

func campoXML(xml, campo string) string {
	_, depois, ok := strings.Cut(xml, "<"+campo)
	if !ok {
		return ""
	}
	_, valor, ok := strings.Cut(depois, ">")
	if !ok {
		return ""
	}
	valor, _, _ = strings.Cut(valor, "</")
	return strings.TrimSpace(valor)
}

func resumir(texto string) string {
	texto = strings.TrimSpace(espacos.ReplaceAllString(texto, " "))
	if runas := []rune(texto); len(runas) > 300 {
		return string(runas[:300])
	}
	return texto
}

// documentoOLE calcula o tamanho de um documento antigo do Office pela tabela de setores
// dele, o unico lugar que diz onde o arquivo termina.
func documentoOLE(f io.ReaderAt, posicao, tamanho int64) *Recuperado {
	cabecalho := make([]byte, 512)
	if _, err := f.ReadAt(cabecalho, posicao); err != nil {
		return nil
	}
	potencia := binary.LittleEndian.Uint16(cabecalho[30:])
	if potencia != 9 && potencia != 12 {
		return nil
	}
	setor := int64(1) << potencia
	// Os primeiros 109 setores da tabela estao no cabecalho, e o resto em uma lista encadeada.
	var setoresTabela []uint32
	for i := 0; i < 109; i++ {
		setoresTabela = append(setoresTabela, binary.LittleEndian.Uint32(cabecalho[76+i*4:]))
	}
	extra := make([]byte, setor)
	proximo := binary.LittleEndian.Uint32(cabecalho[68:])
	for voltas := 0; proximo < 0xfffffffa && voltas < 4096; voltas++ {
		if _, err := f.ReadAt(extra, posicao+(int64(proximo)+1)*setor); err != nil {
			return nil
		}
		for j := int64(0); j+8 <= setor; j += 4 {
			setoresTabela = append(setoresTabela, binary.LittleEndian.Uint32(extra[j:]))
		}
		proximo = binary.LittleEndian.Uint32(extra[setor-4:])
	}
	maior := int64(-1)
	tabela := make([]byte, setor)
	for i, numero := range setoresTabela {
		if numero >= 0xfffffffa {
			continue
		}
		if _, err := f.ReadAt(tabela, posicao+(int64(numero)+1)*setor); err != nil {
			return nil
		}
		for j := int64(0); j+4 <= setor; j += 4 {
			if binary.LittleEndian.Uint32(tabela[j:]) != 0xffffffff {
				if indice := int64(i)*setor/4 + j/4; indice > maior {
					maior = indice
				}
			}
		}
	}
	total := (maior + 2) * setor
	if maior < 0 || posicao+total > tamanho {
		return nil
	}
	r := &Recuperado{Posicao: posicao, Tamanho: total, Extensao: ".ole"}
	// O nome dos fluxos fica perto do fim, entao o documento e lido ate um limite maior.
	amostra := make([]byte, min(total, blocoVarredura))
	if _, err := f.ReadAt(amostra, posicao); err != nil {
		return nil
	}
	for _, tipo := range []struct{ fluxo, extensao string }{
		{"WordDocument", ".doc"}, {"PowerPoint Document", ".ppt"}, {"Workbook", ".xls"}, {"Book", ".xls"},
	} {
		if bytes.Contains(amostra, codificarUTF16(tipo.fluxo)) {
			r.Extensao = tipo.extensao
			break
		}
	}
	r.Texto = resumir(strings.Join(trechosLegiveis(amostra), " "))
	return r
}

func codificarUTF16(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for _, c := range s {
		b = append(b, byte(c), 0)
	}
	return b
}

var (
	frasesUTF16 = regexp.MustCompile(`(?:[\x20-\x7e]\x00){12,}`)
	frasesASCII = regexp.MustCompile(`[\x20-\x7e]{24,}`)
)

// trechosLegiveis tira frases de um documento binario. Nao e o texto formatado, mas basta
// para reconhecer de que documento se trata.
func trechosLegiveis(b []byte) []string {
	var saida []string
	for _, f := range frasesUTF16.FindAll(b, 12) {
		saida = append(saida, strings.ReplaceAll(string(f), "\x00", ""))
	}
	if len(saida) == 0 {
		for _, f := range frasesASCII.FindAll(b, 12) {
			saida = append(saida, string(f))
		}
	}
	return saida
}

// discoOtico le uma imagem UDF sem depender do sistema de arquivos. Devolve false quando a
// imagem nao e UDF, para o chamador tratar como uma imagem nao reconhecida.
func (t *trabalho) discoOtico(segmentos []string) (bool, error) {
	temporario := filepath.Join(t.saida, "otico.tmp")
	saida, err := os.Create(temporario)
	if err != nil {
		return false, err
	}
	defer os.Remove(temporario)
	c := t.comando("img_cat", segmentos...)
	c.Stdout = saida
	erro := c.Run()
	if fechou := saida.Close(); erro == nil {
		erro = fechou
	}
	if erro != nil {
		return false, erro
	}
	f, err := os.Open(temporario)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	inicio := make([]byte, 64*1024)
	n, _ := f.ReadAt(inicio, 0)
	if !EhUDF(inicio[:n]) {
		return false, nil
	}
	nome := filepath.Base(segmentos[0])
	if err := t.registros.Encode(registro{
		Tipo: "alerta", Severidade: "media", Fonte: "Imagem de disco",
		Descricao:   "Disco óptico em UDF: " + nome + ". A leitura normal não abre este formato, então as entradas de diretório e os documentos abaixo vêm de uma varredura por assinatura. Datas e caminhos podem estar incompletos.",
		OrigemLocal: nome,
		Dados:       map[string]any{"imagem": nome, "formato": "UDF"},
	}); err != nil {
		return true, err
	}
	if err := t.entradasUDF(f, info.Size(), nome); err != nil {
		return true, err
	}
	return true, t.documentos(f, info.Size(), segmentos, nome)
}

func (t *trabalho) entradasUDF(f io.ReaderAt, tamanho int64, nome string) error {
	buffer := make([]byte, blocoVarredura)
	vistas := map[string]bool{}
	for inicio := int64(0); inicio < tamanho; inicio += blocoVarredura - 4096 {
		n, err := f.ReadAt(buffer, inicio)
		if err != nil && err != io.EOF {
			return err
		}
		for _, e := range InterpretarEntradasUDF(buffer[:n], inicio) {
			texto := "Entrada de diretório no disco: " + e.Nome
			switch {
			case e.Apagada && e.Pasta:
				texto = "Pasta apagada do disco: " + e.Nome
			case e.Apagada:
				texto = "Arquivo apagado do disco: " + e.Nome
			case e.Pasta:
				texto = "Pasta no disco: " + e.Nome
			}
			if vistas[texto] {
				continue
			}
			vistas[texto] = true
			r := registro{
				Tipo: "evento", Fonte: "Disco óptico", Descricao: texto,
				OrigemLocal: nome + ", posição " + strconv.FormatInt(e.Posicao, 10),
				Dados:       map[string]any{"caminho": e.Nome, "posicao": e.Posicao, "apagado": e.Apagada, "pasta": e.Pasta},
			}
			if !e.Pasta {
				r.Entidades = []entidade{{Tipo: "arquivo", Valor: strings.TrimPrefix(e.Nome, "?")}}
			}
			if err := t.registros.Encode(r); err != nil {
				return err
			}
		}
		if n < blocoVarredura {
			break
		}
	}
	return nil
}

func (t *trabalho) documentos(f io.ReaderAt, tamanho int64, segmentos []string, nome string) error {
	achados, err := CarregarDocumentos(f, tamanho)
	if err != nil {
		return err
	}
	for _, r := range achados {
		t.extraidos++
		relativo := filepath.Join("derivados", strconv.Itoa(t.extraidos))
		destino := filepath.Join(t.saida, relativo)
		if err := os.MkdirAll(filepath.Dir(destino), 0o755); err != nil {
			return err
		}
		soma, err := copiarTrecho(f, r.Posicao, r.Tamanho, destino)
		if err != nil {
			return err
		}
		nomeArquivo := fmt.Sprintf("recuperado-%d%s", r.Posicao, r.Extensao)
		if err := t.derivados.Encode(Derivado{
			Arquivo: filepath.ToSlash(relativo), Nome: nomeArquivo,
			Origem: nome + "!" + nomeArquivo, Evidencia: segmentos[0],
		}); err != nil {
			return err
		}
		descricao := fmt.Sprintf("Documento recuperado pelo conteúdo (%s, %d bytes): %s %s", r.Extensao, r.Tamanho, r.Titulo, r.Texto)
		if err := t.registros.Encode(registro{
			Tipo: "evento", Quando: r.Alterado, Fonte: "Disco óptico",
			Descricao:   strings.TrimSpace(descricao),
			OrigemLocal: nome + ", posição " + strconv.FormatInt(r.Posicao, 10),
			Entidades:   []entidade{{Tipo: "hash", Valor: soma}},
			Dados: map[string]any{
				"arquivo": nomeArquivo, "posicao": r.Posicao, "tamanho": r.Tamanho, "titulo": r.Titulo,
				"criado": r.Criado, "alterado": r.Alterado, "texto": r.Texto, "sha256": soma,
			},
		}); err != nil {
			return err
		}
	}
	return nil
}

func copiarTrecho(f io.ReaderAt, posicao, tamanho int64, destino string) (string, error) {
	saida, err := os.Create(destino)
	if err != nil {
		return "", err
	}
	defer saida.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(saida, h), io.NewSectionReader(f, posicao, tamanho)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
