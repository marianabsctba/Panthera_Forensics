// Package relatorio gera um documento unico e autocontido, pronto para imprimir ou
// anexar. Todo valor vem da evidencia e nao e confiavel, por isso o html/template
// escapa tudo e o documento proibe a execucao de scripts.
package relatorio

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/internal/custodia"
	"github.com/marianabsctba/Panthera_Forensics/internal/marca"
)

// LimiteAchados evita um documento impraticavel; o que ficar de fora e informado.
const LimiteAchados = 500

type dados struct {
	Caso          caso.Info
	Gerado        string
	Resumo        caso.Resumo
	Achados       []caso.Linha
	AchadosFora   int64
	Evidencias    []caso.Evidencia
	Execucoes     []caso.Execucao
	NaoExecutados []custodia.Entrada
	Custodia      []custodia.Entrada
	CustodiaOK    bool
	CustodiaErro  string
	HashFinal     string
	Simbolo       template.URL
}

// Gerar escreve o relatorio e registra na custodia o hash do documento gerado.
func Gerar(c *caso.Caso, w io.Writer) error {
	d := dados{
		Caso:    c.Info,
		Gerado:  time.Now().UTC().Format("2006-01-02 15:04:05") + " UTC",
		Simbolo: template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(marca.Simbolo)),
	}
	var err error
	if d.Resumo, err = c.Resumir(); err != nil {
		return err
	}
	if d.Achados, err = c.Consultar(caso.Filtro{Tipo: "alerta", Ordem: "gravidade", Limite: LimiteAchados}); err != nil {
		return err
	}
	var total int64
	for _, n := range d.Resumo.Alertas {
		total += n
	}
	if fora := total - int64(len(d.Achados)); fora > 0 {
		d.AchadosFora = fora
	}
	if d.Evidencias, err = c.Evidencias(); err != nil {
		return err
	}
	if d.Execucoes, err = c.Execucoes(); err != nil {
		return err
	}
	if d.Custodia, err = custodia.Ler(filepath.Join(c.Dir, "custodia.jsonl")); err != nil {
		return err
	}
	if err := custodia.Verificar(d.Custodia); err != nil {
		d.CustodiaErro = err.Error()
	} else {
		d.CustodiaOK = true
	}
	if n := len(d.Custodia); n > 0 {
		d.HashFinal = d.Custodia[n-1].Hash
	}
	for _, e := range d.Custodia {
		if e.Acao == "modulo.nao_executado" {
			d.NaoExecutados = append(d.NaoExecutados, e)
		}
	}
	var html strings.Builder
	if err := modelo.Execute(&html, d); err != nil {
		return err
	}
	soma := sha256.Sum256([]byte(html.String()))
	if _, err := c.Custodia.Registrar("relatorio.gerado", map[string]any{"sha256": hex.EncodeToString(soma[:])}); err != nil {
		return err
	}
	_, err = io.WriteString(w, html.String())
	return err
}

// Salvar grava o relatorio na pasta do caso e devolve o caminho.
func Salvar(c *caso.Caso) (string, error) {
	caminho := filepath.Join(c.Dir, "relatorio-"+time.Now().UTC().Format("20060102-150405")+".html")
	f, err := os.Create(caminho)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := Gerar(c, f); err != nil {
		return "", err
	}
	return caminho, f.Close()
}

var nomesSeveridade = map[string]string{"critica": "Crítica", "alta": "Alta", "media": "Média", "baixa": "Baixa", "info": "Informativa"}

var modelo = template.Must(template.New("relatorio").Funcs(template.FuncMap{
	"severidade": func(s string) string {
		if n, ok := nomesSeveridade[s]; ok {
			return n
		}
		return s
	},
	"unir": func(a []string) string { return strings.Join(a, " ") },
	"curto": func(s string) string {
		if len(s) >= 19 {
			return strings.Replace(s[:19], "T", " ", 1)
		}
		return s
	},
}).Parse(`<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>Relatório: {{.Caso.Nome}}</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;color:#ededed;background:#0b0b0b;max-width:1000px;margin:0 auto;padding:32px 16px}
.capa{display:flex;align-items:center;gap:16px}.capa img{width:64px;height:64px;border-radius:10px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 8px;color:#ff5cc0;border-bottom:1px solid #ff1fa8;padding-bottom:4px}
table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}th,td{text-align:left;border-bottom:1px solid #2a2a2a;padding:5px 8px 5px 0;vertical-align:top}
th{font-weight:600}code{font:11px ui-monospace,Consolas,monospace;word-break:break-all}
.meta{color:#9a9a9a}.ok{color:#ff5cc0;font-weight:600}.ruim{color:#ff6b6b;font-weight:600}
/* No papel, fundo preto gasta tinta e prejudica a leitura de um anexo. */
@media print{body{padding:0;color:#111;background:#fff}h2{color:#b0126f;break-after:avoid}th,td{border-color:#ddd}.meta{color:#555}.ok{color:#b0126f}.ruim{color:#a01616}tr{break-inside:avoid}}
</style>
</head>
<body>
<div class="capa"><img src="{{.Simbolo}}" alt="Símbolo da Panthera"><div>
<h1>{{.Caso.Nome}}</h1>
<p class="meta">{{if .Caso.Numero}}{{.Caso.Numero}} · {{end}}{{if .Caso.Perito}}Responsável: {{.Caso.Perito}} · {{end}}Gerado em {{.Gerado}}</p>
</div></div>

<h2>Resumo</h2>
<p>{{.Resumo.Evidencias}} evidência(s), {{.Resumo.Registros}} registro(s) e {{.Resumo.Entidades}} entidade(s).
{{if .Resumo.Inicio}}Período observado, em UTC: {{curto .Resumo.Inicio}} a {{curto .Resumo.Fim}}.{{end}}</p>
<p>Os achados abaixo foram gerados automaticamente e são pontos de partida para o exame. Cada um precisa ser conferido na evidência de origem antes de sustentar qualquer conclusão.</p>
{{if .Resumo.ExecucoesErro}}<p class="ruim">{{.Resumo.ExecucoesErro}} etapa(s) de processamento falharam. Veja a metodologia.</p>{{end}}
{{if .NaoExecutados}}<p class="ruim">{{len .NaoExecutados}} leitura(s) aplicáveis não foram executadas. Veja a metodologia.</p>{{end}}

<h2>Achados</h2>
{{if .Achados}}<table><tr><th>Gravidade</th><th>Quando (UTC)</th><th>Achado</th><th>Fonte</th><th>Origem</th></tr>
{{range .Achados}}<tr><td>{{severidade .Severidade}}</td><td>{{if .Quando}}{{curto .Quando}}{{else}}{{.QuandoBruto}}{{end}}</td><td>{{.Descricao}}</td><td>{{.Fonte}}</td><td><code>{{.OrigemArquivo}}{{if .OrigemLocal}} #{{.OrigemLocal}}{{end}}</code></td></tr>
{{end}}</table>{{else}}<p>Nenhum achado automático. Isso não significa ausência de atividade relevante.</p>{{end}}
{{if .AchadosFora}}<p class="meta">Mais {{.AchadosFora}} achado(s) de menor gravidade constam no caso e não foram listados aqui.</p>{{end}}

<h2>Evidências</h2>
<table><tr><th>#</th><th>Nome</th><th>Origem</th><th>Bytes</th><th>Hashes</th></tr>
{{range .Evidencias}}<tr><td>{{.ID}}</td><td>{{.Nome}}</td><td><code>{{.Origem}}</code></td><td>{{.Tamanho}}</td><td><code>SHA-256 {{.SHA256}}<br>SHA-1 {{.SHA1}}<br>MD5 {{.MD5}}</code></td></tr>
{{end}}</table>

<h2>Metodologia</h2>
<table><tr><th>Etapa</th><th>Módulo e versão</th><th>Estado</th><th>Registros</th><th>Início e fim (UTC)</th><th>Executável e parâmetros</th></tr>
{{range .Execucoes}}<tr><td>{{.Titulo}}</td><td>{{.Modulo}} {{.Versao}}</td><td>{{.Estado}}{{if .Erro}}: {{.Erro}}{{end}}</td><td>{{.Registros}}</td><td>{{.Inicio}}<br>{{.Fim}}</td><td><code>SHA-256 {{.FerramentaSHA256}}<br>{{unir .Args}}</code></td></tr>
{{end}}</table>
{{range .NaoExecutados}}<p class="ruim">Não executado: {{index .Detalhes "modulo"}}. Motivo: {{index .Detalhes "motivo"}}.</p>{{end}}

<h2>Cadeia de custódia</h2>
{{if .CustodiaOK}}<p class="ok">Encadeamento íntegro em {{len .Custodia}} registro(s).</p>{{else}}<p class="ruim">Encadeamento com problema: {{.CustodiaErro}}</p>{{end}}
<p>Hash final no momento da geração: <code>{{.HashFinal}}</code>. Guarde este valor fora do caso: comparar com ele é o que permite detectar a remoção dos registros mais recentes.</p>
<table><tr><th>#</th><th>Quando (UTC)</th><th>Autor</th><th>Ação</th><th>Hash</th></tr>
{{range .Custodia}}<tr><td>{{.Seq}}</td><td>{{.Quando}}</td><td>{{.Autor}}</td><td>{{.Acao}}</td><td><code>{{.Hash}}</code></td></tr>
{{end}}</table>
</body>
</html>
`))
