package caso

import (
	"database/sql"
	"encoding/json"
	"strings"
)

// Linha e um registro pronto para exibicao.
type Linha struct {
	ID            int64           `json:"id"`
	Tipo          string          `json:"tipo"`
	Quando        string          `json:"quando"`
	QuandoBruto   string          `json:"quando_bruto,omitempty"`
	Fonte         string          `json:"fonte"`
	Descricao     string          `json:"descricao"`
	Severidade    string          `json:"severidade"`
	OrigemArquivo string          `json:"origem_arquivo"`
	OrigemLocal   string          `json:"origem_local"`
	Modulo        string          `json:"modulo"`
	Dados         json.RawMessage `json:"dados,omitempty"`
	Entidades     []EntidadeCaso  `json:"entidades,omitempty"`
}

// EntidadeCaso e uma identidade do caso e quantos registros a citam.
type EntidadeCaso struct {
	ID        int64  `json:"id"`
	Tipo      string `json:"tipo"`
	Valor     string `json:"valor"`
	Registros int64  `json:"registros,omitempty"`
}

// Resumo alimenta a primeira tela do caso.
type Resumo struct {
	Registros     int64            `json:"registros"`
	Alertas       map[string]int64 `json:"alertas"`
	Evidencias    int64            `json:"evidencias"`
	Entidades     int64            `json:"entidades"`
	Inicio        string           `json:"inicio"`
	Fim           string           `json:"fim"`
	ExecucoesErro int64            `json:"execucoes_erro"`
}

// Filtro restringe uma consulta de registros.
type Filtro struct {
	Texto      string
	Tipo       string
	Severidade string
	EntidadeID int64
	Limite     int
	Deslocar   int
	Ordem      string
	// De e Ate limitam o periodo por prefixo de data em UTC, como "2004-08".
	De       string
	Ate      string
	Fonte    string
	Marcados bool
}

// condicoes monta o WHERE comum as consultas de registros.
func (f Filtro) condicoes() (de string, onde []string, args []any) {
	de = `registros r JOIN execucoes x ON x.id=r.execucao_id`
	if t := termosBusca(f.Texto); t != "" {
		de += ` JOIN busca b ON b.rowid=r.id`
		onde = append(onde, `busca MATCH ?`)
		args = append(args, t)
	}
	if f.Tipo != "" {
		onde = append(onde, `r.tipo=?`)
		args = append(args, f.Tipo)
	}
	if f.Severidade != "" {
		onde = append(onde, `r.severidade=?`)
		args = append(args, f.Severidade)
	}
	if f.EntidadeID != 0 {
		onde = append(onde, `r.id IN (SELECT registro_id FROM registro_entidade WHERE entidade_id=?)`)
		args = append(args, f.EntidadeID)
	}
	if f.De != "" {
		onde = append(onde, `r.quando>=?`)
		args = append(args, f.De)
	}
	if f.Ate != "" {
		// O til vem depois de digitos e letras: inclui tudo o que comeca com o prefixo.
		onde = append(onde, `r.quando<?`)
		args = append(args, f.Ate+"~")
	}
	if f.Fonte != "" {
		onde = append(onde, `r.fonte=?`)
		args = append(args, f.Fonte)
	}
	if f.Marcados {
		onde = append(onde, `r.id IN (SELECT registro_id FROM marcacoes)`)
	}
	return de, onde, args
}

const colunas = `r.id,r.tipo,COALESCE(r.quando,''),r.quando_bruto,r.fonte,r.descricao,r.severidade,r.origem_arquivo,r.origem_local,x.titulo`

// OrdemSeveridade coloca os achados mais graves primeiro.
const ordemSeveridade = `CASE r.severidade WHEN 'critica' THEN 0 WHEN 'alta' THEN 1 WHEN 'media' THEN 2 WHEN 'baixa' THEN 3 WHEN 'info' THEN 4 ELSE 5 END`

// Resumir conta o que existe no caso.
func (c *Caso) Resumir() (Resumo, error) {
	r := Resumo{Alertas: map[string]int64{}}
	limite := limiteFuturo()
	err := c.DB.QueryRow(`SELECT COUNT(*),COALESCE(MIN(CASE WHEN quando<? THEN quando END),''),COALESCE(MAX(CASE WHEN quando<? THEN quando END),'') FROM registros`, limite, limite).Scan(&r.Registros, &r.Inicio, &r.Fim)
	if err != nil {
		return r, err
	}
	for consulta, destino := range map[string]*int64{
		`SELECT COUNT(*) FROM evidencias`:                      &r.Evidencias,
		`SELECT COUNT(*) FROM entidades`:                       &r.Entidades,
		`SELECT COUNT(*) FROM execucoes WHERE estado='falhou'`: &r.ExecucoesErro,
	} {
		if err := c.DB.QueryRow(consulta).Scan(destino); err != nil {
			return r, err
		}
	}
	linhas, err := c.DB.Query(`SELECT severidade,COUNT(*) FROM registros WHERE tipo='alerta' GROUP BY severidade`)
	if err != nil {
		return r, err
	}
	defer linhas.Close()
	for linhas.Next() {
		var s string
		var n int64
		if err := linhas.Scan(&s, &n); err != nil {
			return r, err
		}
		r.Alertas[s] = n
	}
	return r, linhas.Err()
}

// Consultar devolve registros conforme o filtro.
func (c *Caso) Consultar(f Filtro) ([]Linha, error) {
	if f.Limite <= 0 || f.Limite > 1000 {
		f.Limite = 200
	}
	de, onde, args := f.condicoes()
	q := `SELECT ` + colunas + ` FROM ` + de
	if len(onde) > 0 {
		q += ` WHERE ` + strings.Join(onde, ` AND `)
	}
	// Registro sem data fica no fim, visivel, em vez de sumir da timeline.
	if f.Ordem == "gravidade" {
		q += ` ORDER BY ` + ordemSeveridade + `, r.quando IS NULL, r.quando, r.id`
	} else {
		q += ` ORDER BY r.quando IS NULL, r.quando, r.id`
	}
	q += ` LIMIT ? OFFSET ?`
	args = append(args, f.Limite, f.Deslocar)
	linhas, err := c.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer linhas.Close()
	todas := []Linha{}
	for linhas.Next() {
		l, err := lerLinha(linhas)
		if err != nil {
			return nil, err
		}
		todas = append(todas, l)
	}
	return todas, linhas.Err()
}

func lerLinha(s interface{ Scan(...any) error }) (Linha, error) {
	var l Linha
	err := s.Scan(&l.ID, &l.Tipo, &l.Quando, &l.QuandoBruto, &l.Fonte, &l.Descricao, &l.Severidade, &l.OrigemArquivo, &l.OrigemLocal, &l.Modulo)
	return l, err
}

// termosBusca transforma o que foi digitado em termos literais do indice, para que
// sinais como - : e * em um hash ou IP nao virem operadores da busca.
func termosBusca(texto string) string {
	var termos []string
	for _, t := range strings.Fields(texto) {
		termos = append(termos, `"`+strings.ReplaceAll(t, `"`, `""`)+`"`)
	}
	return strings.Join(termos, " ")
}

// Detalhe devolve um registro completo, com dados originais e entidades.
func (c *Caso) Detalhe(id int64) (Linha, error) {
	var dados string
	var l Linha
	err := c.DB.QueryRow(`SELECT `+colunas+`,r.dados FROM registros r JOIN execucoes x ON x.id=r.execucao_id WHERE r.id=?`, id).
		Scan(&l.ID, &l.Tipo, &l.Quando, &l.QuandoBruto, &l.Fonte, &l.Descricao, &l.Severidade, &l.OrigemArquivo, &l.OrigemLocal, &l.Modulo, &dados)
	if err != nil {
		return l, err
	}
	l.Dados = json.RawMessage(dados)
	linhas, err := c.DB.Query(`SELECT e.id,e.tipo,e.valor,(SELECT COUNT(*) FROM registro_entidade WHERE entidade_id=e.id)
		FROM registro_entidade re JOIN entidades e ON e.id=re.entidade_id WHERE re.registro_id=? ORDER BY e.tipo,e.valor`, id)
	if err != nil {
		return l, err
	}
	defer linhas.Close()
	for linhas.Next() {
		var e EntidadeCaso
		if err := linhas.Scan(&e.ID, &e.Tipo, &e.Valor, &e.Registros); err != nil {
			return l, err
		}
		l.Entidades = append(l.Entidades, e)
	}
	return l, linhas.Err()
}

// Entidades lista as identidades mais citadas.
func (c *Caso) Entidades(tipo string, limite int) ([]EntidadeCaso, error) {
	if limite <= 0 || limite > 1000 {
		limite = 200
	}
	var linhas *sql.Rows
	var err error
	base := `SELECT e.id,e.tipo,e.valor,COUNT(re.registro_id) n FROM entidades e LEFT JOIN registro_entidade re ON re.entidade_id=e.id `
	if tipo != "" {
		linhas, err = c.DB.Query(base+`WHERE e.tipo=? GROUP BY e.id ORDER BY n DESC,e.valor LIMIT ?`, tipo, limite)
	} else {
		linhas, err = c.DB.Query(base+`GROUP BY e.id ORDER BY n DESC,e.valor LIMIT ?`, limite)
	}
	if err != nil {
		return nil, err
	}
	defer linhas.Close()
	todas := []EntidadeCaso{}
	for linhas.Next() {
		var e EntidadeCaso
		if err := linhas.Scan(&e.ID, &e.Tipo, &e.Valor, &e.Registros); err != nil {
			return nil, err
		}
		todas = append(todas, e)
	}
	return todas, linhas.Err()
}

// Execucao e uma etapa de processamento do caso.
type Execucao struct {
	ID               int64    `json:"id"`
	Modulo           string   `json:"modulo"`
	Titulo           string   `json:"titulo"`
	Versao           string   `json:"versao"`
	FerramentaSHA256 string   `json:"ferramenta_sha256"`
	Args             []string `json:"args"`
	Estado           string   `json:"estado"`
	Inicio           string   `json:"inicio"`
	Fim              string   `json:"fim"`
	Erro             string   `json:"erro,omitempty"`
	Registros        int64    `json:"registros"`
}

// Execucoes lista o que ja rodou no caso.
func (c *Caso) Execucoes() ([]Execucao, error) {
	linhas, err := c.DB.Query(`SELECT id,modulo,titulo,versao,ferramenta_sha256,args,estado,inicio,COALESCE(fim,''),erro,registros FROM execucoes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer linhas.Close()
	todas := []Execucao{}
	for linhas.Next() {
		var x Execucao
		var args string
		if err := linhas.Scan(&x.ID, &x.Modulo, &x.Titulo, &x.Versao, &x.FerramentaSHA256, &args, &x.Estado, &x.Inicio, &x.Fim, &x.Erro, &x.Registros); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(args), &x.Args)
		todas = append(todas, x)
	}
	return todas, linhas.Err()
}
