package disco

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// As definicoes de tarefas agendadas sao arquivos XML sem extensao. Elas guardam o comando
// inteiro, que os eventos do sistema nao trazem.
var (
	tarefas = regexp.MustCompile(`(?i)^/windows/system32/tasks/.+`)
	// Programa em pasta de usuario ou temporaria e incomum em tarefa, e comum em ataque.
	pastaDeUsuario = regexp.MustCompile(`(?i)\\(users|temp|programdata|\$recycle\.bin)\\|%(temp|appdata|localappdata|public|userprofile)%`)
)

// Tarefa resume uma definicao de tarefa agendada.
type Tarefa struct {
	Nome     string
	Autor    string
	Conta    string
	Gatilhos []string
	Comandos []string
}

// InterpretarTarefa le o XML ja convertido em texto. Tarefas so com acao COM ficam sem
// comando, mas continuam validas.
func InterpretarTarefa(texto string) (Tarefa, bool) {
	var x struct {
		XMLName xml.Name `xml:"Task"`
		Info    struct {
			Autor string `xml:"Author"`
			URI   string `xml:"URI"`
		} `xml:"RegistrationInfo"`
		Gatilhos struct {
			Itens []struct {
				XMLName xml.Name
				Inicio  string `xml:"StartBoundary"`
			} `xml:",any"`
		} `xml:"Triggers"`
		Contas []struct {
			Usuario string `xml:"UserId"`
			Grupo   string `xml:"GroupId"`
		} `xml:"Principals>Principal"`
		Acoes []struct {
			Comando    string `xml:"Command"`
			Argumentos string `xml:"Arguments"`
		} `xml:"Actions>Exec"`
	}
	d := xml.NewDecoder(strings.NewReader(texto))
	// O texto ja chega em UTF-8, embora o cabecalho do arquivo declare UTF-16.
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := d.Decode(&x); err != nil {
		return Tarefa{}, false
	}
	t := Tarefa{Nome: x.Info.URI, Autor: x.Info.Autor}
	for _, c := range x.Contas {
		if t.Conta == "" {
			t.Conta = c.Usuario + c.Grupo
		}
	}
	for _, g := range x.Gatilhos.Itens {
		t.Gatilhos = append(t.Gatilhos, strings.TrimSpace(g.XMLName.Local+" "+g.Inicio))
	}
	for _, a := range x.Acoes {
		if c := strings.TrimSpace(a.Comando + " " + a.Argumentos); c != "" {
			t.Comandos = append(t.Comandos, c)
		}
	}
	return t, true
}

func registroDaTarefa(t Tarefa, e Entrada, inicio int64) registro {
	nome := t.Nome
	if nome == "" {
		nome = e.Caminho
	}
	partes := []string{"Tarefa agendada " + nome}
	if t.Autor != "" {
		partes = append(partes, "autor "+t.Autor)
	}
	if t.Conta != "" {
		partes = append(partes, "conta "+t.Conta)
	}
	if len(t.Gatilhos) > 0 {
		partes = append(partes, "gatilho "+strings.Join(t.Gatilhos, "; "))
	}
	comando := strings.Join(t.Comandos, "; ")
	if comando != "" {
		partes = append(partes, "comando "+comando)
	}
	r := registro{
		Tipo: "evento", Quando: hora(e.Criacao), Fonte: "Tarefa agendada",
		Descricao:   strings.Join(partes, ", "),
		OrigemLocal: fmt.Sprintf("partição no setor %d, inode %s", inicio, e.Inode),
		Dados: map[string]any{
			"caminho": e.Caminho, "inode": e.Inode, "particao": inicio, "tamanho": e.Tamanho,
			"nome": nome, "autor": t.Autor, "conta": t.Conta, "gatilhos": t.Gatilhos, "comandos": t.Comandos,
		},
	}
	if pastaDeUsuario.MatchString(comando) {
		r.Tipo, r.Severidade = "alerta", "media"
	}
	return r
}

// lerTarefa e como indexarTexto: um arquivo ilegivel nao atrapalha os demais.
func (t *trabalho) lerTarefa(segmentos []string, p Particao, e Entrada) error {
	args := append([]string{"-o", fmt.Sprint(p.Inicio)}, segmentos...)
	conteudo, err := t.comando("icat", append(args, e.Inode)...).Output()
	if err != nil {
		return nil
	}
	texto, ok := TextoLegivel(conteudo)
	if !ok {
		return nil
	}
	tarefa, ok := InterpretarTarefa(texto)
	if !ok {
		return nil
	}
	r := registroDaTarefa(tarefa, e, p.Inicio)
	// Um caso pode ter varias imagens: o inode so faz sentido junto com a imagem certa.
	r.Dados["imagem"] = baseNome(strings.ReplaceAll(segmentos[0], `\`, "/"))
	return t.registros.Encode(r)
}
