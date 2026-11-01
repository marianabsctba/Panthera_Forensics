package caso

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marianabsctba/Panthera_Forensics/internal/custodia"
)

// semear cria um caso com registros sem precisar de ferramentas.
func semear(t *testing.T) *Caso {
	t.Helper()
	c, err := Criar(t.TempDir(), "Analise", "", "perita")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Fechar() })
	res, err := c.DB.Exec(`INSERT INTO execucoes(chave,modulo,titulo,versao,estado,inicio) VALUES('k','m','Leitura','1','concluida','agora')`)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := res.LastInsertId()
	for _, r := range []struct {
		quando, tipo, sev, fonte, desc string
		ents                           []string
	}{
		{"2026-03-01T10:00:00.000000000Z", "evento", "", "A", "um", []string{"pc", "ana"}},
		{"2026-03-01T11:00:00.000000000Z", "alerta", "alta", "A", "dois", []string{"pc", "ana"}},
		{"2026-03-03T09:00:00.000000000Z", "alerta", "alta", "B", "dois", []string{"pc"}},
		{"", "evento", "", "B", "sem data", nil},
	} {
		var quando any
		if r.quando != "" {
			quando = r.quando
		}
		res, err := c.DB.Exec(`INSERT INTO registros(execucao_id,tipo,quando,fonte,descricao,severidade) VALUES(?,?,?,?,?,?)`, x, r.tipo, quando, r.fonte, r.desc, r.sev)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		for _, v := range r.ents {
			tipo := "host"
			if v == "ana" {
				tipo = "usuario"
			}
			var ent int64
			if err := c.DB.QueryRow(`INSERT INTO entidades(tipo,valor) VALUES(?,?) ON CONFLICT(tipo,valor) DO UPDATE SET tipo=excluded.tipo RETURNING id`, tipo, v).Scan(&ent); err != nil {
				t.Fatal(err)
			}
			if _, err := c.DB.Exec(`INSERT INTO registro_entidade VALUES(?,?)`, id, ent); err != nil {
				t.Fatal(err)
			}
		}
	}
	return c
}

func TestAtividadeNaoEscondeDiasVazios(t *testing.T) {
	c := semear(t)
	a, err := c.Atividade(Filtro{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Escala != "hora" {
		t.Fatalf("escala %s", a.Escala)
	}
	if a.SemData != 1 {
		t.Fatalf("registro sem data precisa ser contado: %d", a.SemData)
	}
	soma, alertas, vazios := int64(0), int64(0), 0
	for _, b := range a.Baldes {
		soma += b.Total
		alertas += b.Alertas
		if b.Total == 0 {
			vazios++
		}
	}
	if soma != 3 || alertas != 2 || vazios == 0 {
		t.Fatalf("soma=%d alertas=%d vazios=%d", soma, alertas, vazios)
	}
}

// Carimbo em branco de um executavel, como apareceu no Hacking Case do NIST.
func TestDataFuturaNaoEstragaGraficoNemResumo(t *testing.T) {
	c := semear(t)
	if _, err := c.DB.Exec(`INSERT INTO registros(execucao_id,tipo,quando,descricao) VALUES(1,'evento','2106-02-07T06:28:15.000000000Z','carimbo')`); err != nil {
		t.Fatal(err)
	}
	a, err := c.Atividade(Filtro{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Futuras != 1 || a.Escala != "hora" {
		t.Fatalf("atividade: %+v", a)
	}
	v, err := c.Visao()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(v.NucleoFim, "2106") || strings.HasPrefix(v.Fim, "2106") {
		t.Fatalf("data futura no resumo: %+v", v)
	}
	if linhas, err := c.Consultar(Filtro{Texto: "", De: "2106"}); err != nil || len(linhas) != 1 {
		t.Fatalf("o registro precisa continuar acessivel: %+v %v", linhas, err)
	}
}

func TestAtividadeAmpliaAoFiltrarPeriodo(t *testing.T) {
	c := semear(t)
	a, err := c.Atividade(Filtro{De: "2026-03-01", Ate: "2026-03-01"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Escala != "minuto" {
		t.Fatalf("escala %s", a.Escala)
	}
	linhas, err := c.Consultar(Filtro{De: "2026-03-01", Ate: "2026-03-01"})
	if err != nil {
		t.Fatal(err)
	}
	if len(linhas) != 2 {
		t.Fatalf("o periodo deveria trazer 2 registros, trouxe %d", len(linhas))
	}
}

func TestAtividadeCasoVazio(t *testing.T) {
	c, err := Criar(t.TempDir(), "Vazio", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Fechar()
	a, err := c.Atividade(Filtro{})
	if err != nil || len(a.Baldes) != 0 {
		t.Fatalf("a=%+v err=%v", a, err)
	}
}

func TestVisaoAgrupaAlertas(t *testing.T) {
	c := semear(t)
	v, err := c.Visao()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Alertas) != 1 || v.Alertas[0].Total != 2 || v.Alertas[0].Descricao != "dois" {
		t.Fatalf("alertas: %+v", v.Alertas)
	}
	if len(v.Entidades["host"]) != 1 || v.Entidades["host"][0].Valor != "pc" {
		t.Fatalf("entidades: %+v", v.Entidades)
	}
	if v.NucleoInicio == "" || v.NucleoFim == "" {
		t.Fatalf("periodo vazio: %+v", v)
	}
}

func TestConexoesLigaQuemApareceJunto(t *testing.T) {
	c := semear(t)
	m, err := c.Conexoes(30)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Nos) != 2 || len(m.Ligacoes) != 1 || m.Ligacoes[0].Total != 2 {
		t.Fatalf("mapa: %+v", m)
	}
}

func TestMarcacaoEntraNaCustodia(t *testing.T) {
	c := semear(t)
	if err := c.Marcar(1, " importante "); err != nil {
		t.Fatal(err)
	}
	if err := c.Marcar(1, "nota nova"); err != nil {
		t.Fatal(err)
	}
	marcado, nota, err := c.NotaDe(1)
	if err != nil || !marcado || nota != "nota nova" {
		t.Fatalf("marcado=%v nota=%q err=%v", marcado, nota, err)
	}
	lista, err := c.Marcacoes()
	if err != nil || len(lista) != 1 || lista[0].Nota != "nota nova" {
		t.Fatalf("lista=%+v err=%v", lista, err)
	}
	so, err := c.Consultar(Filtro{Marcados: true})
	if err != nil || len(so) != 1 {
		t.Fatalf("filtro: %+v %v", so, err)
	}
	if err := c.Desmarcar(1); err != nil {
		t.Fatal(err)
	}
	if err := c.Marcar(999, "x"); err == nil {
		t.Fatal("registro inexistente nao pode ser marcado")
	}
	entradas, err := custodia.Ler(filepath.Join(c.Dir, "custodia.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := custodia.Verificar(entradas); err != nil {
		t.Fatal(err)
	}
	acoes := map[string]int{}
	for _, e := range entradas {
		acoes[e.Acao]++
	}
	if acoes["registro.marcado"] != 2 || acoes["registro.desmarcado"] != 1 {
		t.Fatalf("custodia: %v", acoes)
	}
}
