package normaliza

import (
	"os"
	"path/filepath"
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
