package disco

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func entradaUDF(nome []byte, caracteristicas byte) []byte {
	b := make([]byte, 38+len(nome))
	b[0], b[1] = 1, 1
	b[18], b[19] = caracteristicas, byte(len(nome))
	copy(b[38:], nome)
	var soma byte
	for i := 0; i < 16; i++ {
		if i != 4 {
			soma += b[i]
		}
	}
	b[4] = soma
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func TestEntradasUDFInclusiveApagadas(t *testing.T) {
	var imagem []byte
	imagem = append(imagem, entradaUDF(append([]byte{8}, "diary.txt"...), 0)...)
	imagem = append(imagem, entradaUDF(append([]byte{254}, "design"...), 6)...)
	// Soma errada: parece uma entrada, mas e so conteudo de um arquivo.
	falsa := entradaUDF(append([]byte{8}, "lixo.txt"...), 0)
	falsa[4]++
	imagem = append(imagem, falsa...)
	// A entrada que aponta para a pasta de cima nao tem nome.
	imagem = append(imagem, entradaUDF(nil, 10)...)
	imagem = append(imagem, make([]byte, 40)...)
	e := InterpretarEntradasUDF(imagem, 1000)
	if len(e) != 2 {
		t.Fatalf("esperava 2 entradas, veio %+v", e)
	}
	if e[0].Nome != "diary.txt" || e[0].Apagada || e[0].Posicao != 1000 {
		t.Fatalf("primeira entrada: %+v", e[0])
	}
	if e[1].Nome != "?design" || !e[1].Apagada || !e[1].Pasta {
		t.Fatalf("segunda entrada: %+v", e[1])
	}
}

func TestReconheceUDF(t *testing.T) {
	inicio := make([]byte, 40000)
	copy(inicio[32769:], "BEA01")
	if EhUDF(inicio) {
		t.Fatal("sem NSR nao e UDF")
	}
	copy(inicio[34817:], "NSR03")
	if !EhUDF(inicio) {
		t.Fatal("deveria reconhecer UDF")
	}
	if EhUDF(inicio[:100]) {
		t.Fatal("trecho curto nao e UDF")
	}
}

func zipDeTeste(t *testing.T, arquivos map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for nome, conteudo := range arquivos {
		w, err := z.Create(nome)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(conteudo)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestRecuperaDocumentosPeloConteudo(t *testing.T) {
	docx := zipDeTeste(t, map[string]string{
		"word/document.xml": "<w:t>Proposta secreta</w:t>",
		"docProps/core.xml": `<dc:title>Projeto</dc:title><dcterms:created x="y">2015-03-01T10:00:00Z</dcterms:created>`,
	})
	pptx := zipDeTeste(t, map[string]string{"ppt/slides/slide1.xml": "<a:t>Slide inicial</a:t>"})
	ole := documentoOLEDeTeste()
	imagem := make([]byte, 2048*40)
	copy(imagem[2048*2:], docx)
	copy(imagem[2048*10:], pptx)
	copy(imagem[2048*20:], ole)
	achados, err := CarregarDocumentos(bytes.NewReader(imagem), int64(len(imagem)))
	if err != nil {
		t.Fatal(err)
	}
	if len(achados) != 3 {
		t.Fatalf("esperava 3 documentos, veio %+v", achados)
	}
	if achados[0].Extensao != ".docx" || achados[0].Titulo != "Projeto" || !strings.Contains(achados[0].Texto, "Proposta secreta") {
		t.Fatalf("docx: %+v", achados[0])
	}
	if achados[0].Tamanho != int64(len(docx)) {
		t.Fatalf("tamanho do docx: %d, esperado %d", achados[0].Tamanho, len(docx))
	}
	if achados[1].Extensao != ".pptx" || !strings.Contains(achados[1].Texto, "Slide inicial") {
		t.Fatalf("pptx: %+v", achados[1])
	}
	if achados[2].Extensao != ".doc" || achados[2].Tamanho != 512*5 {
		t.Fatalf("doc: %+v", achados[2])
	}
}

// documentoOLEDeTeste tem cabecalho, um setor de tabela e tres setores usados.
func documentoOLEDeTeste() []byte {
	b := make([]byte, 512*5)
	copy(b, marcaOLE)
	binary.LittleEndian.PutUint16(b[30:], 9)
	for i := 0; i < 109; i++ {
		binary.LittleEndian.PutUint32(b[76+i*4:], 0xffffffff)
	}
	binary.LittleEndian.PutUint32(b[76:], 0)
	tabela := b[512 : 512*2]
	for j := 0; j < 512; j += 4 {
		binary.LittleEndian.PutUint32(tabela[j:], 0xffffffff)
	}
	for j := 0; j < 4; j++ {
		binary.LittleEndian.PutUint32(tabela[j*4:], 0xfffffffe)
	}
	copy(b[512*2:], codificarUTF16("WordDocument"))
	copy(b[512*3:], codificarUTF16("Texto longo do documento antigo"))
	return b
}

func TestTextoDasNotas(t *testing.T) {
	var b []byte
	for _, s := range []string{"Root Entry", "Version", "ccbb72fb-d253-11e4-b", "Tomorrow...", "Everything will be OK..."} {
		b = append(b, codificarUTF16(s)...)
		b = append(b, 0xff, 0xfe, 0x01, 0x02)
	}
	if v := TextoDasNotas(b); v != "Tomorrow...\nEverything will be OK..." {
		t.Fatalf("texto: %q", v)
	}
}

func TestEscolheAImagemCertaParaLerArquivo(t *testing.T) {
	grupos := [][]string{{"x/pc.E01", "x/pc.E02"}, {"x/usb.E01"}}
	if g, err := escolherImagem(grupos, "USB.e01"); err != nil || g[0] != "x/usb.E01" {
		t.Fatalf("%v %v", g, err)
	}
	// Sem saber a imagem, nao pode chutar a primeira.
	if _, err := escolherImagem(grupos, ""); err == nil {
		t.Fatal("deveria recusar registro sem imagem em caso com varias")
	}
	if g, err := escolherImagem(grupos[1:], ""); err != nil || g[0] != "x/usb.E01" {
		t.Fatalf("%v %v", g, err)
	}
	if _, err := escolherImagem(grupos, "outra.E01"); err == nil {
		t.Fatal("deveria recusar imagem desconhecida")
	}
}
