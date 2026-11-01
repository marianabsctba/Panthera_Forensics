package normaliza

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
)

func escrever(t *testing.T, conteudo string) string {
	t.Helper()
	caminho := filepath.Join(t.TempDir(), "saida")
	if err := os.WriteFile(caminho, []byte(conteudo), 0o644); err != nil {
		t.Fatal(err)
	}
	return caminho
}

func coletar(t *testing.T, s modulo.Saida, conteudo string) []Registro {
	t.Helper()
	var r []Registro
	if err := Ler(s, escrever(t, conteudo), func(x Registro) error { r = append(r, x); return nil }); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCSVComBOMEVariasDatas(t *testing.T) {
	s := modulo.Saida{Formato: "csv", Mapas: []modulo.Mapa{
		{Tipo: "evento", Quando: "{Criado}", Descricao: "Criado: {Nome}", OrigemLocal: "{Id}", Entidades: []modulo.MapaEntidade{{Tipo: "arquivo", Valor: "{Nome}"}}},
		{Tipo: "evento", Quando: "{Alterado}", Descricao: "Alterado: {Nome}", OrigemLocal: "{Id}"},
	}}
	r := coletar(t, s, "\xEF\xBB\xBFId,Nome,Criado,Alterado\n7,a.txt,2026-03-01 10:00:00.1234567,\n")
	if len(r) != 1 {
		t.Fatalf("data vazia nao deveria gerar registro: %d", len(r))
	}
	if r[0].Quando != "2026-03-01T10:00:00.123456700Z" {
		t.Fatalf("data errada: %s", r[0].Quando)
	}
	if r[0].OrigemLocal != "7" || r[0].Entidades[0].Valor != "a.txt" {
		t.Fatalf("mapeamento errado: %+v", r[0])
	}
}

func TestJSONLComCampoAninhadoESeveridade(t *testing.T) {
	s := modulo.Saida{Formato: "jsonl", Severidades: map[string]string{"crit": "critica"}, Mapas: []modulo.Mapa{
		{Tipo: "alerta", Quando: "{T}", Descricao: "{R} em {D.Host}", Severidade: "{L}"},
	}}
	r := coletar(t, s, `{"T":"2026-03-01 07:00:00.000 -03:00","R":"Regra","L":"crit","D":{"Host":"PC1"}}`+"\n")
	if r[0].Quando != "2026-03-01T10:00:00.000000000Z" {
		t.Fatalf("fuso nao convertido: %s", r[0].Quando)
	}
	if r[0].Severidade != "critica" || r[0].Descricao != "Regra em PC1" {
		t.Fatalf("mapeamento errado: %+v", r[0])
	}
}

func TestSQLiteEntregaTodasAsLinhas(t *testing.T) {
	caminho := filepath.Join(t.TempDir(), "saida.sqlite")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(caminho))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE timeline(t TEXT, n TEXT, q INT);
		INSERT INTO timeline VALUES('2026-03-01 10:00:00.000','a',1),(NULL,'b',NULL)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s := modulo.Saida{Formato: "sqlite", Tabela: "timeline", Mapas: []modulo.Mapa{{Tipo: "evento", Quando: "{t}", Descricao: "{n} {q}", ManterSemData: true}}}
	var r []Registro
	if err := Ler(s, caminho, func(x Registro) error { r = append(r, x); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(r) != 2 || r[0].Descricao != "a 1" || r[0].Quando == "" || r[1].Quando != "" {
		t.Fatalf("linhas erradas: %+v", r)
	}
}

// Formato real do YARA-X: uma linha por arquivo, regras aninhadas e meta em pares.
func TestItensAninhadosComParesEFaixas(t *testing.T) {
	s := modulo.Saida{
		Formato: "jsonl", Itens: "rules", Descartar: []string{"strings"},
		Faixas: map[string]float64{"critica": 90, "alta": 70, "media": 50, "baixa": 0},
		Mapas:  []modulo.Mapa{{Tipo: "alerta", Descricao: "{identifier}: {meta.description}", Severidade: "{meta.score}", OrigemArquivo: "{pai.path}"}},
	}
	r := coletar(t, s, `{"path":"a.exe","rules":[{"identifier":"R1","meta":[["description","d1"],["score",75]],"strings":[1]},{"identifier":"R2","meta":[["score",40]]}]}`+"\n"+`{"path":"b.exe","rules":[]}`+"\n")
	if len(r) != 2 {
		t.Fatalf("esperava 2 registros: %+v", r)
	}
	if r[0].Descricao != "R1: d1" || r[0].Severidade != "alta" || r[0].OrigemArquivo != "a.exe" {
		t.Fatalf("mapeamento errado: %+v", r[0])
	}
	if r[1].Severidade != "baixa" {
		t.Fatalf("faixa errada: %+v", r[1])
	}
	if _, tem := r[0].Dados["strings"]; tem {
		t.Fatal("campo descartado continua nos dados")
	}
}

// Formato real do capa: um documento, com regras em um objeto indexado pelo nome.
func TestDocumentoJSONComObjeto(t *testing.T) {
	s := modulo.Saida{Formato: "json", Itens: "rules", Mapas: []modulo.Mapa{{Tipo: "alerta", Descricao: "{_chave} em {meta.namespace}"}}}
	r := coletar(t, s, `{"meta":{},"rules":{"b":{"meta":{"namespace":"n2"}},"a":{"meta":{"namespace":"n1"}}}}`)
	if len(r) != 2 || r[0].Descricao != "a em n1" || r[1].Descricao != "b em n2" {
		t.Fatalf("itens errados: %+v", r)
	}
}

func TestTSVSemCabecalhoIgnoraComentarios(t *testing.T) {
	s := modulo.Saida{Formato: "tsv", Colunas: []string{"local", "valor", "contexto"}, Mapas: []modulo.Mapa{{Tipo: "evento", Descricao: "{_arquivo}: {valor}", OrigemLocal: "{local}"}}}
	caminho := filepath.Join(t.TempDir(), "email.txt")
	if err := os.WriteFile(caminho, []byte("# comentario\n123\ta@b.c\tctx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var r []Registro
	if err := Ler(s, caminho, func(x Registro) error { r = append(r, x); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(r) != 1 || r[0].Descricao != "email: a@b.c" || r[0].OrigemLocal != "123" {
		t.Fatalf("linha errada: %+v", r)
	}
}

func TestDatasDasFerramentasDeRede(t *testing.T) {
	casos := map[string]string{
		"1093620994.553915":               "2004-08-27T15:36:34",
		"1093620994.553915000":            "2004-08-27T15:36:34",
		"2016-07-13T19:42:07.388030-0300": "2016-07-13T22:42:07",
	}
	for bruto, esperado := range casos {
		obtido, ok := interpretarData(bruto)
		if !ok || !strings.HasPrefix(obtido, esperado) {
			t.Errorf("%s: esperado %s, obtido %s", bruto, esperado, obtido)
		}
	}
	if _, ok := interpretarData("12345"); ok {
		t.Error("numero curto nao e data")
	}
	if q, _ := interpretarData("1093620994.656657934"); q != "2004-08-27T15:36:34.656657934Z" {
		t.Errorf("precisao perdida: %s", q)
	}
	for _, zero := range []string{"1970-01-01T00:00:00.000000+0000", "1601-01-01 00:00:00.0000000", "0001-01-01T00:00:00Z"} {
		if q, ok := interpretarData(zero); ok {
			t.Errorf("marco zero aceito como data: %s vira %s", zero, q)
		}
	}
	if d := limparDescricao("GET a () : "); d != "GET a" {
		t.Errorf("descricao mal limpa: %q", d)
	}
}

func TestDataEmMicrossegundos(t *testing.T) {
	s := modulo.Saida{Formato: "jsonl", Mapas: []modulo.Mapa{{Tipo: "evento", Quando: "{t}", QuandoEscala: "microssegundos", Descricao: "x", ManterSemData: true}}}
	r := coletar(t, s, `{"t":998076043000000}`+"\n"+`{"t":0}`+"\n")
	if r[0].Quando != "2001-08-17T19:20:43.000000000Z" {
		t.Fatalf("data errada: %s", r[0].Quando)
	}
	if r[1].Quando != "" {
		t.Fatalf("marco zero aceito: %s", r[1].Quando)
	}
}

func TestManterSemData(t *testing.T) {
	s := modulo.Saida{Formato: "jsonl", Mapas: []modulo.Mapa{{Tipo: "evento", Quando: "{T}", Descricao: "{N}", ManterSemData: true}}}
	r := coletar(t, s, `{"T":null,"N":"processo"}`+"\n")
	if len(r) != 1 || r[0].Quando != "" {
		t.Fatalf("registro sem data perdido: %+v", r)
	}
}

func TestMapaCondicional(t *testing.T) {
	s := modulo.Saida{Formato: "csv", Mapas: []modulo.Mapa{
		{Tipo: "evento", Descricao: "visto {N}"},
		{Tipo: "evento", Descricao: "apagado {N}", Se: map[string]string{"EmUso": "false"}},
	}}
	r := coletar(t, s, "N,EmUso\na,True\nb,False\n")
	if len(r) != 3 || r[2].Descricao != "apagado b" {
		t.Fatalf("condicao nao aplicada: %+v", r)
	}
}

func TestEntidadeRemoveVariacao(t *testing.T) {
	s := modulo.Saida{Formato: "csv", Mapas: []modulo.Mapa{{Tipo: "evento", Descricao: "x", Entidades: []modulo.MapaEntidade{
		{Tipo: "usuario", Valor: "{U}", Remover: `( \(S-1-[^)]*\)$)|(^-$)`},
	}}}}
	r := coletar(t, s, "U\nBASE\\ana (S-1-5-18)\n-\n")
	if r[0].Entidades[0].Valor != `BASE\ana` {
		t.Fatalf("variacao mantida: %+v", r[0].Entidades)
	}
	if len(r[1].Entidades) != 0 {
		t.Fatalf("valor vazio virou entidade: %+v", r[1].Entidades)
	}
}

func TestDataIlegivelPreservaRegistro(t *testing.T) {
	s := modulo.Saida{Formato: "contrato"}
	r := coletar(t, s, `{"tipo":"evento","descricao":"x","quando":"ontem"}`+"\n")
	if r[0].Quando != "" || r[0].QuandoBruto != "ontem" {
		t.Fatalf("valor original perdido: %+v", r[0])
	}
}

func TestContratoInvalidoFalha(t *testing.T) {
	s := modulo.Saida{Formato: "contrato"}
	err := Ler(s, escrever(t, `{"tipo":"evento"}`+"\n"), func(Registro) error { return nil })
	if err == nil {
		t.Fatal("registro sem descricao deveria falhar")
	}
}
