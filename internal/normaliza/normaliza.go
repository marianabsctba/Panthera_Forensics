// Package normaliza transforma a saida das ferramentas em registros do caso,
// usando apenas o que o manifesto declara.
package normaliza

import (
	"bufio"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
)

// Registro e a unidade da linha do tempo. Tambem e o formato de saida "contrato".
type Registro struct {
	Tipo          string         `json:"tipo"`
	Quando        string         `json:"quando,omitempty"`
	QuandoBruto   string         `json:"quando_bruto,omitempty"`
	Fonte         string         `json:"fonte,omitempty"`
	Descricao     string         `json:"descricao"`
	Severidade    string         `json:"severidade,omitempty"`
	OrigemArquivo string         `json:"origem_arquivo,omitempty"`
	OrigemLocal   string         `json:"origem_local,omitempty"`
	Entidades     []Entidade     `json:"entidades,omitempty"`
	Dados         map[string]any `json:"dados,omitempty"`
}

// Entidade e uma identidade que liga registros de fontes diferentes.
type Entidade struct {
	Tipo  string `json:"tipo"`
	Valor string `json:"valor"`
}

var severidades = map[string]bool{"critica": true, "alta": true, "media": true, "baixa": true, "info": true}

// Ler percorre um arquivo de saida e entrega cada registro produzido.
func Ler(s modulo.Saida, caminho string, entregar func(Registro) error) error {
	if s.Formato == "sqlite" {
		return lerSQLite(s, caminho, entregar)
	}
	f, err := os.Open(caminho)
	if err != nil {
		return err
	}
	defer f.Close()
	leitor := bufio.NewReaderSize(f, 1<<20)
	if inicio, _ := leitor.Peek(3); len(inicio) == 3 && inicio[0] == 0xEF && inicio[1] == 0xBB && inicio[2] == 0xBF {
		leitor.Discard(3)
	}
	switch s.Formato {
	case "contrato":
		return lerLinhas(leitor, func(dados []byte) error {
			var r Registro
			if err := json.Unmarshal(dados, &r); err != nil {
				return err
			}
			if r.Tipo == "" || r.Descricao == "" {
				return errors.New("registro sem tipo ou descricao")
			}
			if r.Quando != "" {
				q, ok := interpretarData(r.Quando)
				if !ok {
					r.QuandoBruto, r.Quando = r.Quando, ""
				} else {
					r.Quando = q
				}
			}
			r.Severidade = normalizarSeveridade(s, r.Severidade)
			return entregar(r)
		})
	case "jsonl":
		return lerLinhas(leitor, func(dados []byte) error {
			var linha map[string]any
			dec := json.NewDecoder(strings.NewReader(string(dados)))
			dec.UseNumber()
			if err := dec.Decode(&linha); err != nil {
				return err
			}
			// Com varios arquivos de saida, o nome diz de qual deles a linha veio.
			if len(s.Somente) > 0 {
				base := filepath.Base(caminho)
				linha["_arquivo"] = strings.TrimSuffix(base, filepath.Ext(base))
			}
			return aplicarItens(s, linha, entregar)
		})
	case "json":
		// Um unico documento, que pode ser grande: a ferramenta nao escreve linha a linha.
		var linha map[string]any
		dec := json.NewDecoder(leitor)
		dec.UseNumber()
		if err := dec.Decode(&linha); err != nil {
			return err
		}
		return aplicarItens(s, linha, entregar)
	case "tsv":
		base := filepath.Base(caminho)
		return lerLinhas(leitor, func(dados []byte) error {
			if len(dados) > 0 && dados[0] == '#' {
				return nil
			}
			campos := strings.Split(string(dados), "\t")
			linha := map[string]any{"_arquivo": strings.TrimSuffix(base, filepath.Ext(base))}
			for i, nome := range s.Colunas {
				if i < len(campos) {
					linha[nome] = campos[i]
				}
			}
			return aplicar(s, linha, entregar)
		})
	case "csv":
		return lerCSV(s, leitor, entregar)
	}
	return fmt.Errorf("formato %q desconhecido", s.Formato)
}

func lerLinhas(r *bufio.Reader, tratar func([]byte) error) error {
	for n := 1; ; n++ {
		linha, err := r.ReadBytes('\n')
		if t := strings.TrimSpace(string(linha)); t != "" {
			if e := tratar([]byte(t)); e != nil {
				return fmt.Errorf("linha %d: %w", n, e)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// lerSQLite entrega cada linha da tabela declarada. O nome da tabela vem do manifesto,
// que ja foi validado, e nunca da saida da ferramenta.
func lerSQLite(s modulo.Saida, caminho string, entregar func(Registro) error) error {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(caminho)+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	linhas, err := db.Query(`SELECT * FROM "` + s.Tabela + `"`)
	if err != nil {
		return err
	}
	defer linhas.Close()
	colunas, err := linhas.Columns()
	if err != nil {
		return err
	}
	valores := make([]any, len(colunas))
	ponteiros := make([]any, len(colunas))
	for i := range valores {
		ponteiros[i] = &valores[i]
	}
	for linhas.Next() {
		if err := linhas.Scan(ponteiros...); err != nil {
			return err
		}
		linha := make(map[string]any, len(colunas))
		for i, v := range valores {
			switch t := v.(type) {
			case nil:
			case []byte:
				linha[colunas[i]] = string(t)
			default:
				linha[colunas[i]] = t
			}
		}
		if err := aplicar(s, linha, entregar); err != nil {
			return err
		}
	}
	return linhas.Err()
}

func lerCSV(s modulo.Saida, r io.Reader, entregar func(Registro) error) error {
	c := csv.NewReader(r)
	c.FieldsPerRecord = -1
	c.LazyQuotes = true
	cabecalho, err := c.Read()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	for {
		colunas, err := c.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		linha := make(map[string]any, len(colunas))
		for i, v := range colunas {
			if i < len(cabecalho) && v != "" {
				linha[cabecalho[i]] = v
			}
		}
		if err := aplicar(s, linha, entregar); err != nil {
			return err
		}
	}
}

// aplicarItens gera um registro por item de uma lista ou objeto aninhado. Campos do
// documento externo ficam em "pai", e a chave de um objeto fica em "_chave".
func aplicarItens(s modulo.Saida, linha map[string]any, entregar func(Registro) error) error {
	if s.Itens == "" {
		return aplicar(s, linha, entregar)
	}
	pai := make(map[string]any, len(linha))
	for k, v := range linha {
		if k != s.Itens {
			pai[k] = v
		}
	}
	entregarItem := func(chave string, v any) error {
		item, ok := v.(map[string]any)
		if !ok {
			item = map[string]any{"valor": v}
		}
		copia := make(map[string]any, len(item)+2)
		for k, valor := range item {
			copia[k] = achatarPares(valor)
		}
		copia["pai"] = pai
		if chave != "" {
			copia["_chave"] = chave
		}
		return aplicar(s, copia, entregar)
	}
	switch itens := buscar(linha, s.Itens).(type) {
	case []any:
		for _, v := range itens {
			if err := entregarItem("", v); err != nil {
				return err
			}
		}
	case map[string]any:
		chaves := make([]string, 0, len(itens))
		for k := range itens {
			chaves = append(chaves, k)
		}
		sort.Strings(chaves)
		for _, k := range chaves {
			if err := entregarItem(k, itens[k]); err != nil {
				return err
			}
		}
	}
	return nil
}

// achatarPares transforma [["nome", valor], ...] em um objeto, para que campos em
// formato de pares possam ser usados nos mapas.
func achatarPares(v any) any {
	lista, ok := v.([]any)
	if !ok || len(lista) == 0 {
		return v
	}
	saida := make(map[string]any, len(lista))
	for _, e := range lista {
		par, ok := e.([]any)
		if !ok || len(par) != 2 {
			return v
		}
		nome, ok := par[0].(string)
		if !ok {
			return v
		}
		saida[nome] = par[1]
	}
	return saida
}

var bytesHex = regexp.MustCompile(`^[0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2})*$`)

// bytesLegiveis tira de 08-00-45-00 o que e texto: os caracteres imprimiveis, sem os
// zeros do UTF-16 nem os bytes de controle de um cabecalho.
func bytesLegiveis(hexa string) string {
	var b strings.Builder
	for _, par := range strings.Split(hexa, "-") {
		if v, err := strconv.ParseUint(par, 16, 8); err == nil && v >= 32 && v < 127 {
			b.WriteByte(byte(v))
		}
	}
	return b.String()
}

func aplicar(s modulo.Saida, linha map[string]any, entregar func(Registro) error) error {
	for _, coluna := range s.Legivel {
		if v, ok := linha[coluna].(string); ok && bytesHex.MatchString(v) {
			linha[coluna+"_legivel"] = bytesLegiveis(v)
		}
	}
	for _, m := range s.Mapas {
		if !condicaoAtendida(m.Se, linha) || (len(m.SeNao) > 0 && condicaoAtendida(m.SeNao, linha)) {
			continue
		}
		if !regexAtendida(m.SeRegex, linha) || (len(m.SeNaoRegex) > 0 && regexAtendida(m.SeNaoRegex, linha)) {
			continue
		}
		bruto := expandir(m.Quando, linha)
		// Um mapa com campo de data declarado e vazio nao gera registro: e o caso
		// de uma linha da MFT sem a quarta data.
		if m.Quando != "" && bruto == "" && !m.ManterSemData {
			continue
		}
		dados := linha
		if len(s.Descartar) > 0 {
			dados = make(map[string]any, len(linha))
			for k, v := range linha {
				dados[k] = v
			}
			for _, campo := range s.Descartar {
				delete(dados, campo)
			}
		}
		r := Registro{
			Tipo:          m.Tipo,
			Fonte:         expandir(m.Fonte, linha),
			Descricao:     limparDescricao(expandir(m.Descricao, linha)),
			Severidade:    normalizarSeveridade(s, expandir(m.Severidade, linha)),
			OrigemArquivo: expandir(m.OrigemArquivo, linha),
			OrigemLocal:   expandir(m.OrigemLocal, linha),
			Dados:         dados,
		}
		if r.Descricao == "" {
			r.Descricao = "(sem descrição)"
		}
		// Data que nao se consegue ler nao descarta o registro: a evidencia fica
		// visivel, com o valor original, fora da ordem da timeline.
		if bruto != "" {
			if q, ok := interpretarData(aplicarEscala(bruto, m.QuandoEscala)); ok {
				r.Quando = q
			} else {
				r.QuandoBruto = bruto
			}
		}
		for _, e := range m.Entidades {
			if !condicaoAtendida(e.Se, linha) {
				continue
			}
			v := expandir(e.Valor, linha)
			if e.Remover != "" {
				padrao, err := compilar(e.Remover)
				if err != nil {
					return err
				}
				v = padrao.ReplaceAllString(v, "")
			}
			if v = strings.TrimSpace(v); v != "" {
				r.Entidades = append(r.Entidades, Entidade{Tipo: expandir(e.Tipo, linha), Valor: v})
			}
		}
		if err := entregar(r); err != nil {
			return err
		}
	}
	return nil
}

var (
	parentesesVazios = regexp.MustCompile(`\(\s*\)`)
	espacosSeguidos  = regexp.MustCompile(`\s{2,}`)
)

// limparDescricao tira o que sobra de um modelo quando campos opcionais vem vazios.
func limparDescricao(texto string) string {
	texto = parentesesVazios.ReplaceAllString(texto, "")
	texto = espacosSeguidos.ReplaceAllString(texto, " ")
	return strings.Trim(texto, " :")
}

// aplicarEscala transforma microssegundos desde 1970 em segundos, sem ponto flutuante.
func aplicarEscala(bruto, escala string) string {
	if escala != "microssegundos" || len(bruto) <= 6 || strings.ContainsAny(bruto, "-.") {
		return bruto
	}
	return bruto[:len(bruto)-6] + "." + bruto[len(bruto)-6:]
}

func condicaoAtendida(se map[string]string, linha map[string]any) bool {
	for campo, esperado := range se {
		if !strings.EqualFold(texto(buscar(linha, campo)), esperado) {
			return false
		}
	}
	return true
}

// regexCompiladas evita recompilar a mesma expressao a cada linha da saida.
var regexCompiladas sync.Map

func regexAtendida(se map[string]string, linha map[string]any) bool {
	for campo, expressao := range se {
		var re *regexp.Regexp
		if guardada, ok := regexCompiladas.Load(expressao); ok {
			re = guardada.(*regexp.Regexp)
		} else {
			// O manifesto ja validou a expressao ao ser carregado.
			re = regexp.MustCompile(expressao)
			regexCompiladas.Store(expressao, re)
		}
		if !re.MatchString(texto(buscar(linha, campo))) {
			return false
		}
	}
	return true
}

func normalizarSeveridade(s modulo.Saida, bruto string) string {
	v := strings.ToLower(strings.TrimSpace(bruto))
	if v == "" {
		return ""
	}
	if mapeada, ok := s.Severidades[v]; ok {
		return mapeada
	}
	if n, err := strconv.ParseFloat(v, 64); err == nil && len(s.Faixas) > 0 {
		melhor, minimo := "info", math.Inf(-1)
		for nome, limite := range s.Faixas {
			if n >= limite && limite > minimo {
				melhor, minimo = nome, limite
			}
		}
		return melhor
	}
	if severidades[v] {
		return v
	}
	return "info"
}

var padroes sync.Map

// compilar guarda as expressoes, porque cada uma e aplicada a todas as linhas.
func compilar(expressao string) (*regexp.Regexp, error) {
	if p, ok := padroes.Load(expressao); ok {
		return p.(*regexp.Regexp), nil
	}
	p, err := regexp.Compile(expressao)
	if err != nil {
		return nil, err
	}
	padroes.Store(expressao, p)
	return p, nil
}

var marcador = regexp.MustCompile(`\{([^{}]+)\}`)

// expandir troca {campo} e {a.b} pelos valores da linha.
func expandir(modelo string, linha map[string]any) string {
	if modelo == "" {
		return ""
	}
	return marcador.ReplaceAllStringFunc(modelo, func(m string) string {
		return texto(buscar(linha, m[1:len(m)-1]))
	})
}

func buscar(linha map[string]any, campo string) any {
	if v, ok := linha[campo]; ok {
		return v
	}
	var atual any = linha
	for _, parte := range strings.Split(campo, ".") {
		mapa, ok := atual.(map[string]any)
		if !ok {
			return nil
		}
		if atual, ok = mapa[parte]; !ok {
			return nil
		}
	}
	return atual
}

func texto(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case json.Number:
		return t.String()
	default:
		dados, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(dados)
	}
}

// epoca reconhece segundos desde 1970, como nas ferramentas de rede. Exigir nove ou dez
// digitos evita tomar um numero qualquer por data.
var epoca = regexp.MustCompile(`^\d{9,10}(\.\d+)?$`)

var formatosComFuso = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999 -07:00",
	"2006-01-02 15:04:05.999999999 Z07:00",
	"2006-01-02T15:04:05.999999999-0700",
	// Data do Java com UTC fixo. Outras abreviacoes de fuso sao ambiguas, e de proposito
	// nao entram: seria melhor mostrar o valor original do que uma hora errada.
	"Mon Jan 02 15:04:05 UTC 2006",
}

var formatosSemFuso = []string{
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999",
	// Tabelas do exame profundo, gravadas com UTC fixo.
	"Jan 02, 2006 15:04:05.999999999",
}

// interpretarData devolve a data em UTC. Sem fuso declarado, assume UTC, que e
// como as ferramentas conectadas gravam.
func interpretarData(bruto string) (string, bool) {
	bruto = strings.TrimSpace(bruto)
	if epoca.MatchString(bruto) {
		// Pelo texto, e nao por ponto flutuante, que perderia precisao nos nanossegundos.
		inteiro, fracao, _ := strings.Cut(bruto, ".")
		segundos, err := strconv.ParseInt(inteiro, 10, 64)
		if err == nil {
			nanos, _ := strconv.ParseInt((fracao + "000000000")[:9], 10, 64)
			return dataValida(time.Unix(segundos, nanos))
		}
	}
	for _, f := range formatosComFuso {
		if t, err := time.Parse(f, bruto); err == nil {
			return dataValida(t)
		}
	}
	for _, f := range formatosSemFuso {
		if t, err := time.ParseInLocation(f, bruto, time.UTC); err == nil {
			return dataValida(t)
		}
	}
	return "", false
}

// dataValida recusa o marco zero, como 1970, 1601 ou o ano 1: e "sem data" escrito como
// data. O valor original fica no registro, fora da ordem da timeline.
func dataValida(t time.Time) (string, bool) {
	if t.Unix() <= 0 {
		return "", false
	}
	return formatar(t), true
}

// formatar usa largura fixa para que a ordem de texto no banco seja a ordem no tempo.
func formatar(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
