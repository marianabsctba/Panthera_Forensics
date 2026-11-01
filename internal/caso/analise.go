package caso

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Balde e uma barra do grafico de atividade.
type Balde struct {
	Periodo string `json:"periodo"`
	Total   int64  `json:"total"`
	Alertas int64  `json:"alertas"`
}

// Atividade e a serie temporal de um filtro.
type Atividade struct {
	Escala  string  `json:"escala"`
	Baldes  []Balde `json:"baldes"`
	SemData int64   `json:"sem_data"`
	// Futuras conta datas depois de hoje, como carimbos em branco de 2106: nao entram no
	// grafico, porque esticariam o eixo a ponto de esconder a atividade real.
	Futuras int64 `json:"futuras"`
}

// limiteFuturo e a primeira data tratada como impossivel. Um dia de folga cobre fusos.
func limiteFuturo() string {
	return time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02")
}

type escala struct {
	nome    string
	tamanho int
	formato string
	passo   func(time.Time) time.Time
}

var escalas = []escala{
	{"minuto", 16, "2006-01-02T15:04", func(t time.Time) time.Time { return t.Add(time.Minute) }},
	{"hora", 13, "2006-01-02T15", func(t time.Time) time.Time { return t.Add(time.Hour) }},
	{"dia", 10, "2006-01-02", func(t time.Time) time.Time { return t.AddDate(0, 0, 1) }},
	{"mes", 7, "2006-01", func(t time.Time) time.Time { return t.AddDate(0, 1, 0) }},
	{"ano", 4, "2006", func(t time.Time) time.Time { return t.AddDate(1, 0, 0) }},
}

// maximoBaldes e o que cabe no grafico sem as barras virarem fios.
const maximoBaldes = 90

// periodos gera a sequencia completa, inclusive os vazios: esconder um periodo sem
// atividade faria dias distantes parecerem vizinhos no grafico.
func (e escala) periodos(inicio, fim string) ([]string, error) {
	t, err := time.Parse(e.formato, inicio[:e.tamanho])
	if err != nil {
		return nil, err
	}
	u, err := time.Parse(e.formato, fim[:e.tamanho])
	if err != nil {
		return nil, err
	}
	var saida []string
	for !t.After(u) {
		saida = append(saida, t.Format(e.formato))
		if len(saida) > maximoBaldes {
			return nil, errGrande
		}
		t = e.passo(t)
	}
	return saida, nil
}

var errGrande = errors.New("periodos demais")

// Atividade agrupa os registros na escala mais fina que ainda cabe no grafico.
func (c *Caso) Atividade(f Filtro) (Atividade, error) {
	a := Atividade{Baldes: []Balde{}}
	de, onde, args := f.condicoes()
	where := ""
	if len(onde) > 0 {
		where = ` WHERE ` + strings.Join(onde, ` AND `)
	}
	limite := limiteFuturo()
	var inicio, fim sql.NullString
	err := c.DB.QueryRow(`SELECT MIN(CASE WHEN r.quando<? THEN r.quando END),MAX(CASE WHEN r.quando<? THEN r.quando END),
		COALESCE(SUM(r.quando IS NULL),0),COALESCE(SUM(r.quando>=?),0) FROM `+de+where,
		append([]any{limite, limite, limite}, args...)...).Scan(&inicio, &fim, &a.SemData, &a.Futuras)
	if err != nil || !inicio.Valid {
		return a, err
	}
	var periodos []string
	var e escala
	for _, candidata := range escalas {
		periodos, err = candidata.periodos(inicio.String, fim.String)
		if err == nil {
			e = candidata
			break
		}
		if !errors.Is(err, errGrande) {
			return a, err
		}
	}
	if e.nome == "" {
		return a, errGrande
	}
	a.Escala = e.nome
	onde = append(onde, `r.quando<?`)
	consulta := append(append([]any{e.tamanho}, args...), limite)
	linhas, err := c.DB.Query(`SELECT substr(r.quando,1,?),COUNT(*),SUM(r.tipo='alerta') FROM `+de+
		` WHERE `+strings.Join(onde, ` AND `)+` GROUP BY 1`, consulta...)
	if err != nil {
		return a, err
	}
	defer linhas.Close()
	valores := map[string]Balde{}
	for linhas.Next() {
		var b Balde
		if err := linhas.Scan(&b.Periodo, &b.Total, &b.Alertas); err != nil {
			return a, err
		}
		valores[b.Periodo] = b
	}
	if err := linhas.Err(); err != nil {
		return a, err
	}
	for _, p := range periodos {
		b := valores[p]
		b.Periodo = p
		a.Baldes = append(a.Baldes, b)
	}
	return a, nil
}

// ContagemFonte e uma opcao do filtro de fontes.
type ContagemFonte struct {
	Fonte string `json:"fonte"`
	Total int64  `json:"total"`
}

// Fontes lista de onde vieram os registros, para o filtro de um clique.
func (c *Caso) Fontes(f Filtro) ([]ContagemFonte, error) {
	f.Fonte = ""
	de, onde, args := f.condicoes()
	q := `SELECT r.fonte,COUNT(*) n FROM ` + de
	if len(onde) > 0 {
		q += ` WHERE ` + strings.Join(onde, ` AND `)
	}
	linhas, err := c.DB.Query(q+` GROUP BY r.fonte ORDER BY n DESC LIMIT 40`, args...)
	if err != nil {
		return nil, err
	}
	defer linhas.Close()
	todas := []ContagemFonte{}
	for linhas.Next() {
		var x ContagemFonte
		if err := linhas.Scan(&x.Fonte, &x.Total); err != nil {
			return nil, err
		}
		todas = append(todas, x)
	}
	return todas, linhas.Err()
}

// AlertaAgrupado e um tipo de achado e quantas vezes apareceu.
type AlertaAgrupado struct {
	Descricao  string `json:"descricao"`
	Severidade string `json:"severidade"`
	Total      int64  `json:"total"`
	Primeiro   string `json:"primeiro"`
}

// VisaoGeral e o resumo do caso em uma tela.
type VisaoGeral struct {
	Resumo       Resumo                    `json:"resumo"`
	Inicio       string                    `json:"inicio"`
	Fim          string                    `json:"fim"`
	NucleoInicio string                    `json:"nucleo_inicio"`
	NucleoFim    string                    `json:"nucleo_fim"`
	Alertas      []AlertaAgrupado          `json:"alertas"`
	Entidades    map[string][]EntidadeCaso `json:"entidades"`
	Leituras     int64                     `json:"leituras"`
	Falhas       int64                     `json:"falhas"`
	Parciais     int64                     `json:"parciais"`
	SemResultado int64                     `json:"sem_resultado"`
	Marcados     int64                     `json:"marcados"`
}

// Visao monta o resumo. Tudo aqui e contagem direta dos registros: nenhuma conclusao e
// inventada, e cada item leva a evidencia na tela.
func (c *Caso) Visao() (VisaoGeral, error) {
	v := VisaoGeral{Entidades: map[string][]EntidadeCaso{}, Alertas: []AlertaAgrupado{}}
	var err error
	if v.Resumo, err = c.Resumir(); err != nil {
		return v, err
	}
	v.Inicio, v.Fim = v.Resumo.Inicio, v.Resumo.Fim
	var comData int64
	limite := limiteFuturo()
	if err := c.DB.QueryRow(`SELECT COUNT(*) FROM registros WHERE quando<?`, limite).Scan(&comData); err != nil {
		return v, err
	}
	if comData > 0 {
		// O miolo de 90% dos registros: datas muito antigas de arquivos do sistema
		// nao dizem quando a maquina foi usada.
		q := `SELECT quando FROM registros WHERE quando<? ORDER BY quando LIMIT 1 OFFSET ?`
		if err := c.DB.QueryRow(q, limite, comData*5/100).Scan(&v.NucleoInicio); err != nil {
			return v, err
		}
		if err := c.DB.QueryRow(q, limite, comData*95/100).Scan(&v.NucleoFim); err != nil {
			return v, err
		}
	}
	linhas, err := c.DB.Query(`SELECT descricao,severidade,COUNT(*) n,COALESCE(MIN(quando),'') FROM registros r WHERE tipo='alerta'
		GROUP BY descricao,severidade ORDER BY ` + ordemSeveridade + `,n DESC LIMIT 12`)
	if err != nil {
		return v, err
	}
	defer linhas.Close()
	for linhas.Next() {
		var a AlertaAgrupado
		if err := linhas.Scan(&a.Descricao, &a.Severidade, &a.Total, &a.Primeiro); err != nil {
			return v, err
		}
		v.Alertas = append(v.Alertas, a)
	}
	if err := linhas.Err(); err != nil {
		return v, err
	}
	for _, tipo := range []string{"host", "usuario", "ip", "dominio", "email", "regra"} {
		lista, err := c.Entidades(tipo, 6)
		if err != nil {
			return v, err
		}
		if len(lista) > 0 {
			v.Entidades[tipo] = lista
		}
	}
	for consulta, destino := range map[string]*int64{
		`SELECT COUNT(*) FROM execucoes WHERE estado='concluida'`:                 &v.Leituras,
		`SELECT COUNT(*) FROM execucoes WHERE estado='falhou'`:                    &v.Falhas,
		`SELECT COUNT(*) FROM execucoes WHERE estado='concluida' AND erro!=''`:    &v.Parciais,
		`SELECT COUNT(*) FROM execucoes WHERE estado='concluida' AND registros=0`: &v.SemResultado,
		`SELECT COUNT(*) FROM marcacoes`:                                          &v.Marcados,
	} {
		if err := c.DB.QueryRow(consulta).Scan(destino); err != nil {
			return v, err
		}
	}
	return v, nil
}

// Ligacao diz quantos registros citam duas entidades juntas.
type Ligacao struct {
	A     int64 `json:"a"`
	B     int64 `json:"b"`
	Total int64 `json:"total"`
}

// MapaConexoes e o grafo das identidades mais citadas.
type MapaConexoes struct {
	Nos      []EntidadeCaso `json:"nos"`
	Ligacoes []Ligacao      `json:"ligacoes"`
}

// Conexoes devolve as identidades que aparecem juntas nos mesmos registros. Aparecer
// junto e so isso: nao prova que uma agiu sobre a outra.
func (c *Caso) Conexoes(limite int) (MapaConexoes, error) {
	m := MapaConexoes{Nos: []EntidadeCaso{}, Ligacoes: []Ligacao{}}
	if limite <= 0 || limite > 60 {
		limite = 30
	}
	// So entidades com ligacoes: as demais apenas poluiriam o mapa.
	linhas, err := c.DB.Query(`WITH par AS (
		SELECT a.entidade_id x,b.entidade_id y,COUNT(*) n FROM registro_entidade a
		JOIN registro_entidade b ON a.registro_id=b.registro_id AND a.entidade_id<b.entidade_id
		GROUP BY 1,2), peso AS (
		SELECT id,SUM(n) n FROM (SELECT x id,n FROM par UNION ALL SELECT y,n FROM par)
		WHERE id NOT IN (SELECT id FROM entidades WHERE tipo='hash') GROUP BY id ORDER BY n DESC LIMIT ?)
		SELECT e.id,e.tipo,e.valor,p.n FROM peso p JOIN entidades e ON e.id=p.id ORDER BY p.n DESC`, limite)
	if err != nil {
		return m, err
	}
	defer linhas.Close()
	nos := map[int64]bool{}
	for linhas.Next() {
		var e EntidadeCaso
		if err := linhas.Scan(&e.ID, &e.Tipo, &e.Valor, &e.Registros); err != nil {
			return m, err
		}
		m.Nos = append(m.Nos, e)
		nos[e.ID] = true
	}
	if err := linhas.Err(); err != nil {
		return m, err
	}
	pares, err := c.DB.Query(`SELECT a.entidade_id,b.entidade_id,COUNT(*) FROM registro_entidade a
		JOIN registro_entidade b ON a.registro_id=b.registro_id AND a.entidade_id<b.entidade_id GROUP BY 1,2`)
	if err != nil {
		return m, err
	}
	defer pares.Close()
	for pares.Next() {
		var l Ligacao
		if err := pares.Scan(&l.A, &l.B, &l.Total); err != nil {
			return m, err
		}
		if nos[l.A] && nos[l.B] {
			m.Ligacoes = append(m.Ligacoes, l)
		}
	}
	return m, pares.Err()
}

// Marcar guarda um achado com a nota do perito, e registra isso na custodia.
func (c *Caso) Marcar(id int64, nota string) error {
	nota = strings.TrimSpace(nota)
	agora := time.Now().UTC().Format(time.RFC3339)
	res, err := c.DB.Exec(`INSERT INTO marcacoes(registro_id,nota,criado)
		SELECT id,?,? FROM registros WHERE id=?
		ON CONFLICT(registro_id) DO UPDATE SET nota=excluded.nota`, nota, agora, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	_, err = c.Custodia.Registrar("registro.marcado", map[string]any{"registro": id, "nota": nota})
	return err
}

// Desmarcar tira a marcacao, e a custodia guarda que ela existiu.
func (c *Caso) Desmarcar(id int64) error {
	res, err := c.DB.Exec(`DELETE FROM marcacoes WHERE registro_id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	_, err = c.Custodia.Registrar("registro.desmarcado", map[string]any{"registro": id})
	return err
}

// Marcacao e um achado guardado pelo perito.
type Marcacao struct {
	Linha
	Nota string `json:"nota"`
}

// Marcacoes lista os achados guardados, em ordem de tempo.
func (c *Caso) Marcacoes() ([]Marcacao, error) {
	linhas, err := c.DB.Query(`SELECT ` + colunas + `,m.nota FROM marcacoes m JOIN registros r ON r.id=m.registro_id
		JOIN execucoes x ON x.id=r.execucao_id ORDER BY r.quando IS NULL,r.quando,r.id`)
	if err != nil {
		return nil, err
	}
	defer linhas.Close()
	todas := []Marcacao{}
	for linhas.Next() {
		var m Marcacao
		l := &m.Linha
		if err := linhas.Scan(&l.ID, &l.Tipo, &l.Quando, &l.QuandoBruto, &l.Fonte, &l.Descricao, &l.Severidade, &l.OrigemArquivo, &l.OrigemLocal, &l.Modulo, &m.Nota); err != nil {
			return nil, err
		}
		todas = append(todas, m)
	}
	return todas, linhas.Err()
}

// NotaDe devolve a marcacao de um registro.
func (c *Caso) NotaDe(id int64) (marcado bool, nota string, err error) {
	err = c.DB.QueryRow(`SELECT nota FROM marcacoes WHERE registro_id=?`, id).Scan(&nota)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	return err == nil, nota, err
}
