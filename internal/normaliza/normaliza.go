// Package normaliza transforma a saida das ferramentas em registros do caso,
// usando apenas o que o manifesto declara.
package normaliza

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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

func aplicar(s modulo.Saida, linha map[string]any, entregar func(Registro) error) error {
	for _, m := range s.Mapas {
		if !condicaoAtendida(m.Se, linha) {
			continue
		}
		bruto := expandir(m.Quando, linha)
		// Um mapa com campo de data declarado e vazio nao gera registro: e o caso
		// de uma linha da MFT sem a quarta data.
		if m.Quando != "" && bruto == "" && !m.ManterSemData {
			continue
		}
		r := Registro{
			Tipo:          m.Tipo,
			Fonte:         expandir(m.Fonte, linha),
			Descricao:     strings.TrimSpace(expandir(m.Descricao, linha)),
			Severidade:    normalizarSeveridade(s, expandir(m.Severidade, linha)),
			OrigemArquivo: expandir(m.OrigemArquivo, linha),
			OrigemLocal:   expandir(m.OrigemLocal, linha),
			Dados:         linha,
		}
		if r.Descricao == "" {
			r.Descricao = "(sem descrição)"
		}
		// Data que nao se consegue ler nao descarta o registro: a evidencia fica
		// visivel, com o valor original, fora da ordem da timeline.
		if bruto != "" {
			if q, ok := interpretarData(bruto); ok {
				r.Quando = q
			} else {
				r.QuandoBruto = bruto
			}
		}
		for _, e := range m.Entidades {
			v := expandir(e.Valor, linha)
			if e.Remover != "" {
				padrao, err := compilar(e.Remover)
				if err != nil {
					return err
				}
				v = padrao.ReplaceAllString(v, "")
			}
			if v = strings.TrimSpace(v); v != "" {
				r.Entidades = append(r.Entidades, Entidade{Tipo: e.Tipo, Valor: v})
			}
		}
		if err := entregar(r); err != nil {
			return err
		}
	}
	return nil
}

func condicaoAtendida(se map[string]string, linha map[string]any) bool {
	for campo, esperado := range se {
		if !strings.EqualFold(texto(buscar(linha, campo)), esperado) {
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

var formatosComFuso = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999 -07:00",
	"2006-01-02 15:04:05.999999999 Z07:00",
	"2006-01-02T15:04:05.999999999-0700",
}

var formatosSemFuso = []string{
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999",
}

// interpretarData devolve a data em UTC. Sem fuso declarado, assume UTC, que e
// como as ferramentas conectadas gravam.
func interpretarData(bruto string) (string, bool) {
	bruto = strings.TrimSpace(bruto)
	for _, f := range formatosComFuso {
		if t, err := time.Parse(f, bruto); err == nil {
			return formatar(t), true
		}
	}
	for _, f := range formatosSemFuso {
		if t, err := time.ParseInLocation(f, bruto, time.UTC); err == nil {
			return formatar(t), true
		}
	}
	return "", false
}

// formatar usa largura fixa para que a ordem de texto no banco seja a ordem no tempo.
func formatar(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
