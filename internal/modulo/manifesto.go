// Package modulo define o contrato entre o nucleo e os modulos. O nucleo nao
// conhece nenhuma ferramenta: tudo o que sabe sobre elas vem do manifesto.
package modulo

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// VersaoContrato e a versao do contrato que este nucleo entende.
const VersaoContrato = 1

// Manifesto descreve um modulo: o que reconhece, o que consome e como roda.
type Manifesto struct {
	Contrato   int                `yaml:"contrato"`
	Nome       string             `yaml:"nome"`
	Titulo     string             `yaml:"titulo"`
	Versao     string             `yaml:"versao"`
	Ferramenta string             `yaml:"ferramenta"`
	Reconhece  []Reconhecimento   `yaml:"reconhece"`
	Consome    []string           `yaml:"consome"`
	Modo       string             `yaml:"modo"`
	Instalar   map[string]Pacote  `yaml:"instalar"`
	Comando    map[string]Comando `yaml:"comando"`
	Saida      Saida              `yaml:"saida"`
	// IgnorarDerivados limita o modulo ao que foi entregue diretamente, para ferramentas
	// lentas demais para os milhares de arquivos extraidos de um disco.
	IgnorarDerivados bool `yaml:"ignorar_derivados"`
	// RequerWSL indica que a ferramenta roda no ambiente Linux dedicado.
	RequerWSL bool `yaml:"requer_wsl"`
	// Opcional deixa o modulo fora da analise padrao: so roda no exame profundo.
	Opcional bool `yaml:"opcional"`
	// Abrir aponta para um programa de analise que a ferramenta deixa na pasta de saida.
	Abrir string `yaml:"abrir"`

	// Dir e a pasta do manifesto, quando ele vem do disco.
	Dir string `yaml:"-"`
}

// Reconhecimento ensina o nucleo a identificar um tipo de evidencia.
type Reconhecimento struct {
	Tipo         string   `yaml:"tipo"`
	MagicaHex    string   `yaml:"magica_hex"`
	Deslocamento int64    `yaml:"deslocamento"`
	Extensoes    []string `yaml:"extensoes"`
	Nomes        []string `yaml:"nomes"`
}

// Pacote aponta para o que deve ser baixado e o hash que ele precisa ter.
type Pacote struct {
	URL    string `yaml:"url"`
	SHA256 string `yaml:"sha256"`
	// Arquivo indica que o download e o proprio executavel, com este nome.
	Arquivo string `yaml:"arquivo"`
	// Extras sao pacotes abertos na mesma pasta, como um conjunto de regras.
	Extras []Pacote `yaml:"extras"`
}

// Comando e a linha de execucao, com marcadores como {entrada} e {saida}. Dir
// "ferramenta" roda na pasta da ferramenta, em vez da pasta de saida, e Stdout grava
// a saida padrao em um arquivo, para ferramentas que so escrevem nela.
type Comando struct {
	Dir    string   `yaml:"dir"`
	Stdout string   `yaml:"stdout"`
	Exec   string   `yaml:"exec"`
	Args   []string `yaml:"args"`
	// Sistema indica que Exec vem do sistema, e nao de uma ferramenta instalada aqui.
	Sistema bool `yaml:"sistema"`
	// ParcialAceita aproveita o que a ferramenta escreveu antes de um erro, como em uma
	// captura de rede cortada no meio de um pacote. O resultado fica marcado como parcial.
	ParcialAceita bool `yaml:"parcial_aceita"`
	// Verificar sao os argumentos de um teste de que a ferramenta esta disponivel.
	Verificar []string `yaml:"verificar"`
	// Versao sao os argumentos que imprimem a versao real, registrada na custodia. Serve
	// para ferramentas sem hash fixado, como as instaladas por um gerenciador de pacotes.
	Versao []string `yaml:"versao"`
}

// Saida descreve como transformar o que a ferramenta escreve em registros.
type Saida struct {
	Arquivos string `yaml:"arquivos"`
	Formato  string `yaml:"formato"`
	// Derivados aponta para um JSONL com arquivos extraidos, que viram novas evidencias.
	Derivados string `yaml:"derivados"`
	// Tabela e a tabela lida quando o formato e sqlite.
	Tabela string `yaml:"tabela"`
	// Somente limita a leitura a estes nomes de arquivo, sem extensao.
	Somente []string `yaml:"somente"`
	// Derivar lista arquivos da saida que viram novas evidencias, sem precisar de lista.
	Derivar []string `yaml:"derivar"`
	// Itens aponta para uma lista ou objeto dentro de cada linha, com um registro por item.
	Itens string `yaml:"itens"`
	// Colunas nomeia os campos do formato tsv, que nao tem cabecalho.
	Colunas []string `yaml:"colunas"`
	// Descartar tira campos enormes dos dados de cada registro. A saida bruta continua
	// preservada na pasta da execucao.
	Descartar []string `yaml:"descartar"`
	// Faixas converte uma pontuacao em gravidade, pelo valor minimo de cada uma.
	Faixas      map[string]float64 `yaml:"faixas"`
	Severidades map[string]string  `yaml:"severidades"`
	Mapas       []Mapa             `yaml:"mapas"`
}

// Mapa gera um registro por linha de saida. Um mesmo arquivo pode ter varios,
// como uma linha da MFT que traz quatro datas diferentes.
type Mapa struct {
	// QuandoEscala declara a unidade de uma data numerica: "microssegundos" desde 1970.
	QuandoEscala string `yaml:"quando_escala"`
	// Se limita o mapa as linhas em que estas colunas tem estes valores.
	Se map[string]string `yaml:"se"`
	// ManterSemData preserva a linha mesmo sem data: um processo sem hora de inicio
	// ainda e um achado, ao contrario de uma das quatro datas vazias da MFT.
	ManterSemData bool           `yaml:"manter_sem_data"`
	Tipo          string         `yaml:"tipo"`
	Quando        string         `yaml:"quando"`
	Fonte         string         `yaml:"fonte"`
	Descricao     string         `yaml:"descricao"`
	Severidade    string         `yaml:"severidade"`
	OrigemArquivo string         `yaml:"origem_arquivo"`
	OrigemLocal   string         `yaml:"origem_local"`
	Entidades     []MapaEntidade `yaml:"entidades"`
}

// MapaEntidade liga uma coluna a uma identidade unica no caso.
type MapaEntidade struct {
	Tipo  string `yaml:"tipo"`
	Valor string `yaml:"valor"`
	// Remover e uma expressao regular tirada do valor, para que a mesma identidade
	// escrita de formas diferentes vire uma so. Valor que fica vazio nao gera entidade.
	Remover string `yaml:"remover"`
	// Se limita esta entidade as linhas em que estas colunas tem estes valores.
	Se map[string]string `yaml:"se"`
}

var nomeValido = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

var tabelaValida = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Interpretar le um manifesto e confere o contrato.
func Interpretar(dados []byte) (*Manifesto, error) {
	var m Manifesto
	dec := yaml.NewDecoder(strings.NewReader(string(dados)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if err := m.validar(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifesto) validar() error {
	if m.Contrato != VersaoContrato {
		return fmt.Errorf("contrato %d nao suportado", m.Contrato)
	}
	if !nomeValido.MatchString(m.Nome) {
		return fmt.Errorf("nome de modulo invalido: %q", m.Nome)
	}
	if m.Titulo == "" || m.Versao == "" {
		return fmt.Errorf("%s: titulo e versao sao obrigatorios", m.Nome)
	}
	if len(m.Consome) == 0 {
		return fmt.Errorf("%s: consome esta vazio", m.Nome)
	}
	switch m.Modo {
	case "":
		m.Modo = "arquivo"
	case "arquivo", "lote", "pasta", "imagem":
	default:
		return fmt.Errorf("%s: modo %q desconhecido", m.Nome, m.Modo)
	}
	if m.Ferramenta == "" {
		m.Ferramenta = m.Nome
	}
	if len(m.Comando) == 0 {
		return fmt.Errorf("%s: sem comando", m.Nome)
	}
	switch m.Saida.Formato {
	case "contrato":
	case "csv", "jsonl", "json", "tsv", "sqlite":
		if m.Saida.Formato == "tsv" && len(m.Saida.Colunas) == 0 {
			return fmt.Errorf("%s: formato tsv exige colunas", m.Nome)
		}
		if len(m.Saida.Mapas) == 0 {
			return fmt.Errorf("%s: formato %s exige mapas", m.Nome, m.Saida.Formato)
		}
		if m.Saida.Formato == "sqlite" && !tabelaValida.MatchString(m.Saida.Tabela) {
			return fmt.Errorf("%s: tabela invalida: %q", m.Nome, m.Saida.Tabela)
		}
	default:
		return fmt.Errorf("%s: formato de saida %q desconhecido", m.Nome, m.Saida.Formato)
	}
	for _, mapa := range m.Saida.Mapas {
		for _, e := range mapa.Entidades {
			if _, err := regexp.Compile(e.Remover); err != nil {
				return fmt.Errorf("%s: remover invalido: %w", m.Nome, err)
			}
		}
	}
	if m.Saida.Arquivos == "" {
		return fmt.Errorf("%s: saida.arquivos e obrigatorio", m.Nome)
	}
	for _, p := range m.Instalar {
		if p.URL == "" || len(p.SHA256) != 64 {
			return fmt.Errorf("%s: pacote de instalacao precisa de url e sha256", m.Nome)
		}
	}
	return nil
}

// ComandoAtual devolve o comando deste sistema, se o modulo roda aqui.
func (m *Manifesto) ComandoAtual() (Comando, bool) {
	c, ok := m.Comando[runtime.GOOS]
	return c, ok
}

// PacoteAtual devolve o pacote de instalacao deste sistema.
func (m *Manifesto) PacoteAtual() (Pacote, bool) {
	p, ok := m.Instalar[runtime.GOOS+"-"+runtime.GOARCH]
	return p, ok
}

// CarregarFS le manifestos de um sistema de arquivos no formato <nome>/modulo.yaml.
func CarregarFS(sistema fs.FS) ([]*Manifesto, error) {
	caminhos, err := fs.Glob(sistema, "*/modulo.yaml")
	if err != nil {
		return nil, err
	}
	var todos []*Manifesto
	for _, c := range caminhos {
		dados, err := fs.ReadFile(sistema, c)
		if err != nil {
			return nil, err
		}
		m, err := Interpretar(dados)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c, err)
		}
		if m.Nome != path.Dir(c) {
			return nil, fmt.Errorf("%s: nome %q difere da pasta", c, m.Nome)
		}
		todos = append(todos, m)
	}
	return todos, nil
}

// CarregarPasta le manifestos do disco e guarda a pasta de cada um.
func CarregarPasta(dir string) ([]*Manifesto, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}
	todos, err := CarregarFS(os.DirFS(dir))
	if err != nil {
		return nil, err
	}
	for _, m := range todos {
		m.Dir = filepath.Join(dir, m.Nome)
	}
	return todos, nil
}

// Combinar une conjuntos de modulos. Um modulo posterior substitui o de mesmo nome.
func Combinar(conjuntos ...[]*Manifesto) []*Manifesto {
	porNome := map[string]*Manifesto{}
	for _, c := range conjuntos {
		for _, m := range c {
			porNome[m.Nome] = m
		}
	}
	todos := make([]*Manifesto, 0, len(porNome))
	for _, m := range porNome {
		todos = append(todos, m)
	}
	sort.Slice(todos, func(i, j int) bool { return todos[i].Nome < todos[j].Nome })
	return todos
}
