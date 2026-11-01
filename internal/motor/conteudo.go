package motor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/internal/disco"
	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
	"github.com/marianabsctba/Panthera_Forensics/internal/processo"
)

// AchadoConteudo e um arquivo que cita os termos buscados.
type AchadoConteudo struct {
	Nome      string `json:"nome"`
	Caminho   string `json:"caminho"`
	Categoria string `json:"categoria"`
	Tamanho   string `json:"tamanho"`
	Apagado   string `json:"apagado"`
	MD5       string `json:"md5"`
}

// ResultadoConteudo e a resposta de uma busca no indice do exame profundo.
type ResultadoConteudo struct {
	Total   int64            `json:"total"`
	Achados []AchadoConteudo `json:"achados"`
}

// moduloConsulta encontra a ultima execucao concluida de um modulo que sabe consultar.
func (m *Motor) moduloConsulta(c *caso.Caso) (*modulo.Manifesto, string, bool) {
	execucoes, err := c.Execucoes()
	if err != nil {
		return nil, "", false
	}
	for i := len(execucoes) - 1; i >= 0; i-- {
		x := execucoes[i]
		if x.Estado != "concluida" {
			continue
		}
		for _, md := range m.Modulos {
			if md.Nome == x.Modulo && md.Consulta != nil {
				return md, filepath.Join(c.Dir, "execucoes", strconv.FormatInt(x.ID, 10), "saida"), true
			}
		}
	}
	return nil, "", false
}

// ExameFeito diz se o caso ja tem um indice que pode ser consultado.
func (m *Motor) ExameFeito(c *caso.Caso) bool {
	_, _, ok := m.moduloConsulta(c)
	return ok
}

// BuscarConteudo consulta o indice como um processo oculto.
func (m *Motor) BuscarConteudo(ctx context.Context, c *caso.Caso, termos string, limite int) (ResultadoConteudo, error) {
	res := ResultadoConteudo{Achados: []AchadoConteudo{}}
	md, dirSaida, ok := m.moduloConsulta(c)
	if !ok {
		return res, errors.New("exame profundo nao realizado")
	}
	dirFerramenta := filepath.Join(m.DirFerramentas, md.Ferramenta, md.Versao)
	args := expandirArgs(md.Consulta.Args, map[string]string{
		"{ferramenta}": dirFerramenta, "{saida}": dirSaida, "{limite}": strconv.Itoa(limite),
		"{regras}": filepath.Join(filepath.Dir(m.DirFerramentas), "regras"), "{termos}": termos,
	})
	ctx, cancelar := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelar()
	cmd := processo.Ocultar(exec.CommandContext(ctx, filepath.Join(dirFerramenta, filepath.FromSlash(md.Consulta.Exec)), args...))
	cmd.Dir = dirFerramenta
	saida, err := cmd.Output()
	if err != nil {
		return res, err
	}
	leitor := bufio.NewScanner(strings.NewReader(string(saida)))
	leitor.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	primeira := true
	for leitor.Scan() {
		linha := strings.TrimSpace(leitor.Text())
		if !strings.HasPrefix(linha, "{") {
			continue
		}
		if primeira {
			primeira = false
			if err := json.Unmarshal([]byte(linha), &res); err != nil {
				return res, err
			}
			res.Achados = []AchadoConteudo{}
			continue
		}
		var a AchadoConteudo
		if err := json.Unmarshal([]byte(linha), &a); err != nil {
			return res, err
		}
		res.Achados = append(res.Achados, a)
	}
	if primeira {
		return res, fmt.Errorf("resposta vazia da consulta")
	}
	return res, leitor.Err()
}

// LerArquivo devolve o conteudo do arquivo de um registro da leitura de disco. Devolve
// tambem o tamanho total, que pode ser maior do que o limite pedido.
func (m *Motor) LerArquivo(ctx context.Context, c *caso.Caso, registro, limite int64) ([]byte, int64, error) {
	l, err := c.Detalhe(registro)
	if err != nil {
		return nil, 0, err
	}
	var d struct {
		Inode    string `json:"inode"`
		Imagem   string `json:"imagem"`
		Particao *int64 `json:"particao"`
		Tamanho  int64  `json:"tamanho"`
		Residual bool   `json:"residual"`
		SHA256   string `json:"sha256"`
	}
	if err := json.Unmarshal(l.Dados, &d); err != nil {
		return nil, 0, err
	}
	// Arquivo que veio solto ou dentro de um pacote ja esta no cofre, pelo proprio hash.
	if d.SHA256 != "" && d.Inode == "" {
		f, err := os.Open(c.CaminhoEvidencia(d.SHA256))
		if err != nil {
			return nil, 0, err
		}
		defer f.Close()
		var leitor io.Reader = f
		if limite > 0 {
			leitor = io.LimitReader(f, limite)
		}
		conteudo, err := io.ReadAll(leitor)
		return conteudo, d.Tamanho, err
	}
	if d.Inode == "" || d.Particao == nil || d.Residual {
		return nil, 0, errors.New("este registro nao aponta para um arquivo da imagem")
	}
	var execucao int64
	var nomeModulo string
	if err := c.DB.QueryRow(`SELECT x.id,x.modulo FROM registros r JOIN execucoes x ON x.id=r.execucao_id WHERE r.id=?`, registro).Scan(&execucao, &nomeModulo); err != nil {
		return nil, 0, err
	}
	dirEntrada := filepath.Join(c.Dir, "execucoes", strconv.FormatInt(execucao, 10), "entrada")
	if _, err := os.Stat(dirEntrada); err != nil {
		return nil, 0, err
	}
	dirBin := ""
	for _, md := range m.Modulos {
		if md.Nome != nomeModulo {
			continue
		}
		cmd, ok := md.ComandoAtual()
		if !ok {
			break
		}
		// A pasta de binarios ja esta declarada no manifesto, depois de -bin.
		for i, a := range cmd.Args {
			if a == "-bin" && i+1 < len(cmd.Args) {
				dirBin = strings.ReplaceAll(cmd.Args[i+1], "{ferramenta}", filepath.Join(m.DirFerramentas, md.Ferramenta, md.Versao))
			}
		}
	}
	if dirBin == "" {
		return nil, 0, errors.New("leitura de conteudo indisponivel para esta fonte")
	}
	conteudo, err := disco.LerArquivo(dirBin, dirEntrada, d.Imagem, *d.Particao, d.Inode, limite)
	if err != nil {
		return nil, 0, err
	}
	return conteudo, d.Tamanho, nil
}
