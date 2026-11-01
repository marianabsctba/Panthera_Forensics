// Package motor identifica evidencias, monta o plano a partir dos manifestos e
// executa os modulos como processos separados. Nada aqui conhece uma ferramenta.
package motor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
	"github.com/marianabsctba/Panthera_Forensics/internal/normaliza"
)

// Motor executa modulos sobre casos.
type Motor struct {
	Modulos        []*modulo.Manifesto
	DirFerramentas string
	TempoMaximo    time.Duration
}

// Tarefa e um modulo com as evidencias que ele deve receber.
type Tarefa struct {
	Modulo   *modulo.Manifesto
	Entradas []caso.Evidencia
}

// Progresso informa o que esta acontecendo, em texto de tela.
type Progresso func(etapa string, feitas, total int)

// Resultado resume um processamento.
type Resultado struct {
	Executadas   int      `json:"executadas"`
	Reutilizadas int      `json:"reutilizadas"`
	Falhas       []string `json:"falhas"`
	Ausentes     []string `json:"ausentes"`
	SemModulo    int      `json:"sem_modulo"`
}

// Identificar descobre o tipo de um arquivo. A assinatura vale mais que o nome,
// porque extensao se troca com facilidade.
func (m *Motor) Identificar(caminho, nome string) (string, error) {
	f, err := os.Open(caminho)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, md := range m.Modulos {
		for _, r := range md.Reconhece {
			if r.MagicaHex == "" {
				continue
			}
			magica, err := hex.DecodeString(r.MagicaHex)
			if err != nil {
				return "", fmt.Errorf("%s: magica invalida: %w", md.Nome, err)
			}
			lido := make([]byte, len(magica))
			if _, err := f.ReadAt(lido, r.Deslocamento); err == nil && bytes.Equal(lido, magica) {
				return r.Tipo, nil
			}
		}
	}
	ext := strings.ToLower(filepath.Ext(nome))
	for _, md := range m.Modulos {
		for _, r := range md.Reconhece {
			for _, n := range r.Nomes {
				if strings.EqualFold(n, nome) {
					return r.Tipo, nil
				}
			}
			for _, x := range r.Extensoes {
				if ext != "" && strings.EqualFold(x, ext) {
					return r.Tipo, nil
				}
			}
		}
	}
	return "", nil
}

// Planejar identifica as evidencias e cruza com o que cada modulo consome.
func (m *Motor) Planejar(c *caso.Caso) ([]Tarefa, Resultado, error) {
	var res Resultado
	evidencias, err := c.Evidencias()
	if err != nil {
		return nil, res, err
	}
	porTipo := map[string][]caso.Evidencia{}
	for _, e := range evidencias {
		if e.Tipo == "" {
			tipo, err := m.Identificar(c.CaminhoEvidencia(e.SHA256), e.Nome)
			if err != nil {
				return nil, res, err
			}
			if tipo != "" {
				if _, err := c.DB.Exec(`UPDATE evidencias SET tipo=? WHERE id=?`, tipo, e.ID); err != nil {
					return nil, res, err
				}
				e.Tipo = tipo
			}
		}
		if e.Tipo == "" {
			res.SemModulo++
			continue
		}
		porTipo[e.Tipo] = append(porTipo[e.Tipo], e)
	}
	var tarefas []Tarefa
	for _, md := range m.Modulos {
		var entradas []caso.Evidencia
		for _, tipo := range md.Consome {
			entradas = append(entradas, porTipo[tipo]...)
		}
		if len(entradas) == 0 {
			continue
		}
		if _, err := m.localizar(md); err != nil {
			res.Ausentes = append(res.Ausentes, md.Titulo)
			continue
		}
		if md.Modo == "lote" {
			tarefas = append(tarefas, Tarefa{Modulo: md, Entradas: unicas(entradas)})
			continue
		}
		for _, e := range unicas(entradas) {
			tarefas = append(tarefas, Tarefa{Modulo: md, Entradas: []caso.Evidencia{e}})
		}
	}
	return tarefas, res, nil
}

// unicas tira duplicatas de conteudo: o mesmo arquivo so precisa ser lido uma vez.
func unicas(todas []caso.Evidencia) []caso.Evidencia {
	vistos := map[string]bool{}
	var saida []caso.Evidencia
	for _, e := range todas {
		if !vistos[e.SHA256] {
			vistos[e.SHA256] = true
			saida = append(saida, e)
		}
	}
	return saida
}

// Processar roda o plano inteiro em sequencia. Uma falha nao interrompe os outros
// modulos: ela fica registrada no caso e na custodia.
func (m *Motor) Processar(ctx context.Context, c *caso.Caso, avisar Progresso) (Resultado, error) {
	tarefas, res, err := m.Planejar(c)
	if err != nil {
		return res, err
	}
	for _, titulo := range res.Ausentes {
		if _, err := c.Custodia.Registrar("modulo.nao_executado", map[string]any{"modulo": titulo, "motivo": "não instalado neste sistema"}); err != nil {
			return res, err
		}
	}
	for i, t := range tarefas {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if avisar != nil {
			avisar(t.Modulo.Titulo, i, len(tarefas))
		}
		reutilizada, err := m.Executar(ctx, c, t)
		switch {
		case err != nil:
			res.Falhas = append(res.Falhas, t.Modulo.Titulo+": "+err.Error())
		case reutilizada:
			res.Reutilizadas++
		default:
			res.Executadas++
		}
	}
	if avisar != nil {
		avisar("", len(tarefas), len(tarefas))
	}
	return res, nil
}

// localizar encontra o executavel declarado. O caminho e relativo a ferramenta
// instalada ou, sem instalacao, a pasta do modulo, e aceita curinga.
func (m *Motor) localizar(md *modulo.Manifesto) (ferramenta, error) {
	cmd, ok := md.ComandoAtual()
	if !ok {
		return ferramenta{}, errors.New("modulo nao roda neste sistema")
	}
	dir := filepath.Join(m.DirFerramentas, md.Ferramenta, md.Versao)
	if _, temPacote := md.PacoteAtual(); !temPacote && md.Dir != "" {
		dir = md.Dir
	}
	achados, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(cmd.Exec)))
	if err != nil {
		return ferramenta{}, err
	}
	sort.Strings(achados)
	if len(achados) == 0 {
		return ferramenta{}, fmt.Errorf("%s nao encontrado em %s", cmd.Exec, dir)
	}
	return ferramenta{dir: dir, exec: achados[0]}, nil
}

type ferramenta struct{ dir, exec string }

// Executar roda uma tarefa, a menos que a mesma entrada ja tenha sido processada
// com a mesma ferramenta e os mesmos argumentos.
func (m *Motor) Executar(ctx context.Context, c *caso.Caso, t Tarefa) (reutilizada bool, err error) {
	md := t.Modulo
	fer, err := m.localizar(md)
	if err != nil {
		return false, err
	}
	comando, _ := md.ComandoAtual()
	shaFerramenta, err := hashArquivo(fer.exec)
	if err != nil {
		return false, err
	}
	chave := chaveTarefa(md, shaFerramenta, comando, t.Entradas)
	var existente int64
	err = c.DB.QueryRow(`SELECT id FROM execucoes WHERE chave=? AND estado='concluida' LIMIT 1`, chave).Scan(&existente)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	inicio := time.Now().UTC().Format(time.RFC3339)
	res, err := c.DB.Exec(`INSERT INTO execucoes(chave,modulo,titulo,versao,ferramenta_sha256,args,estado,inicio) VALUES(?,?,?,?,?,?,?,?)`,
		chave, md.Nome, md.Titulo, md.Versao, shaFerramenta, "[]", "rodando", inicio)
	if err != nil {
		return false, err
	}
	id, _ := res.LastInsertId()
	dirExec := filepath.Join(c.Dir, "execucoes", fmt.Sprint(id))
	dirEntrada, dirSaida := filepath.Join(dirExec, "entrada"), filepath.Join(dirExec, "saida")
	if err := os.MkdirAll(dirSaida, 0o755); err != nil {
		return false, m.falhar(c, id, md, err)
	}
	entrada, err := prepararEntrada(c, dirEntrada, md.Modo, t.Entradas)
	if err != nil {
		return false, m.falhar(c, id, md, err)
	}
	args := expandirArgs(comando.Args, map[string]string{
		"{entrada}": entrada, "{saida}": dirSaida, "{ferramenta}": fer.dir,
	})
	argsJSON, _ := json.Marshal(args)
	if _, err := c.DB.Exec(`UPDATE execucoes SET args=? WHERE id=?`, string(argsJSON), id); err != nil {
		return false, m.falhar(c, id, md, err)
	}
	dirTrabalho := dirSaida
	if comando.Dir == "ferramenta" {
		dirTrabalho = fer.dir
	}
	arquivoSaida := filepath.Join(dirExec, "stdout.log")
	if comando.Stdout != "" {
		arquivoSaida = filepath.Join(dirSaida, filepath.Base(comando.Stdout))
	}
	if err := m.rodar(ctx, fer.exec, args, dirTrabalho, arquivoSaida, filepath.Join(dirExec, "stderr.log")); err != nil {
		return false, m.falhar(c, id, md, err)
	}
	n, err := importar(c, id, md, dirSaida)
	if err != nil {
		return false, m.falhar(c, id, md, fmt.Errorf("ao ler a saida: %w", err))
	}
	fim := time.Now().UTC().Format(time.RFC3339)
	if _, err := c.DB.Exec(`UPDATE execucoes SET estado='concluida',fim=?,registros=? WHERE id=?`, fim, n, id); err != nil {
		return false, err
	}
	shas := make([]string, 0, len(t.Entradas))
	for _, e := range t.Entradas {
		shas = append(shas, e.SHA256)
	}
	_, err = c.Custodia.Registrar("modulo.executado", map[string]any{
		"execucao": id, "modulo": md.Nome, "versao": md.Versao, "ferramenta_sha256": shaFerramenta,
		"args": args, "entradas": shas, "registros": n,
	})
	return false, err
}

func (m *Motor) falhar(c *caso.Caso, id int64, md *modulo.Manifesto, causa error) error {
	fim := time.Now().UTC().Format(time.RFC3339)
	// Uma importacao interrompida nao deixa registros parciais, porque ocorre em
	// uma unica transacao; nada mais precisa ser desfeito aqui.
	if _, err := c.DB.Exec(`UPDATE execucoes SET estado='falhou',fim=?,erro=? WHERE id=?`, fim, causa.Error(), id); err != nil {
		return errors.Join(causa, err)
	}
	if _, err := c.Custodia.Registrar("modulo.falhou", map[string]any{"execucao": id, "modulo": md.Nome, "erro": causa.Error()}); err != nil {
		return errors.Join(causa, err)
	}
	return causa
}

func (m *Motor) rodar(ctx context.Context, executavel string, args []string, dirTrabalho, arquivoSaida, arquivoErros string) error {
	limite := m.TempoMaximo
	if limite <= 0 {
		limite = 12 * time.Hour
	}
	ctx, cancelar := context.WithTimeout(ctx, limite)
	defer cancelar()
	saida, err := os.Create(arquivoSaida)
	if err != nil {
		return err
	}
	defer saida.Close()
	erros, err := os.Create(arquivoErros)
	if err != nil {
		return err
	}
	defer erros.Close()
	cmd := exec.CommandContext(ctx, executavel, args...)
	cmd.Dir = dirTrabalho
	cmd.Stdout, cmd.Stderr = saida, erros
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("interrompido: %w", ctx.Err())
		}
		return fmt.Errorf("%w; veja %s", err, arquivoErros)
	}
	return nil
}

// prepararEntrada expoe a evidencia com o nome original, sem copiar: um link fisico
// para o arquivo do cofre, que e somente leitura.
func prepararEntrada(c *caso.Caso, dir, modo string, entradas []caso.Evidencia) (string, error) {
	var ultimo string
	for i, e := range entradas {
		sub := filepath.Join(dir, fmt.Sprint(i))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return "", err
		}
		ultimo = filepath.Join(sub, nomeSeguro(e.Nome))
		if err := os.Link(c.CaminhoEvidencia(e.SHA256), ultimo); err != nil {
			return "", err
		}
	}
	if modo == "lote" {
		return dir, nil
	}
	return ultimo, nil
}

var inseguro = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)

// nomeSeguro impede que um nome vindo da evidencia escape da pasta de trabalho.
func nomeSeguro(nome string) string {
	limpo := strings.Trim(inseguro.ReplaceAllString(nome, "_"), ". ")
	if limpo == "" {
		return "evidencia"
	}
	return limpo
}

func expandirArgs(modelo []string, valores map[string]string) []string {
	args := make([]string, len(modelo))
	for i, a := range modelo {
		for k, v := range valores {
			a = strings.ReplaceAll(a, k, v)
		}
		args[i] = a
	}
	return args
}

func chaveTarefa(md *modulo.Manifesto, shaFerramenta string, cmd modulo.Comando, entradas []caso.Evidencia) string {
	shas := make([]string, 0, len(entradas))
	for _, e := range entradas {
		shas = append(shas, e.SHA256)
	}
	sort.Strings(shas)
	h := sha256.New()
	json.NewEncoder(h).Encode([]any{md.Nome, md.Versao, shaFerramenta, cmd, md.Saida, shas})
	return hex.EncodeToString(h.Sum(nil))
}

func importar(c *caso.Caso, execucao int64, md *modulo.Manifesto, dirSaida string) (int64, error) {
	arquivos, err := filepath.Glob(filepath.Join(dirSaida, filepath.FromSlash(md.Saida.Arquivos)))
	if err != nil {
		return 0, err
	}
	if len(arquivos) == 0 {
		return 0, nil
	}
	sort.Strings(arquivos)
	tx, err := c.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	inserir, err := tx.Prepare(`INSERT INTO registros(execucao_id,tipo,quando,quando_bruto,fonte,descricao,severidade,origem_arquivo,origem_local,dados) VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer inserir.Close()
	indexar, err := tx.Prepare(`INSERT INTO busca(rowid,descricao,fonte,dados) VALUES(?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer indexar.Close()
	criarEntidade, err := tx.Prepare(`INSERT INTO entidades(tipo,valor) VALUES(?,?) ON CONFLICT(tipo,valor) DO UPDATE SET tipo=excluded.tipo RETURNING id`)
	if err != nil {
		return 0, err
	}
	defer criarEntidade.Close()
	ligar, err := tx.Prepare(`INSERT OR IGNORE INTO registro_entidade(registro_id,entidade_id) VALUES(?,?)`)
	if err != nil {
		return 0, err
	}
	defer ligar.Close()

	var n int64
	for _, arquivo := range arquivos {
		err := normaliza.Ler(md.Saida, arquivo, func(r normaliza.Registro) error {
			dados, err := json.Marshal(r.Dados)
			if err != nil {
				return err
			}
			var quando any
			if r.Quando != "" {
				quando = r.Quando
			}
			res, err := inserir.Exec(execucao, r.Tipo, quando, r.QuandoBruto, r.Fonte, r.Descricao, r.Severidade, r.OrigemArquivo, r.OrigemLocal, string(dados))
			if err != nil {
				return err
			}
			id, err := res.LastInsertId()
			if err != nil {
				return err
			}
			if _, err := indexar.Exec(id, r.Descricao, r.Fonte, string(dados)); err != nil {
				return err
			}
			for _, e := range r.Entidades {
				var ent int64
				if err := criarEntidade.QueryRow(e.Tipo, e.Valor).Scan(&ent); err != nil {
					return err
				}
				if _, err := ligar.Exec(id, ent); err != nil {
					return err
				}
			}
			n++
			return nil
		})
		if err != nil {
			return 0, fmt.Errorf("%s: %w", filepath.Base(arquivo), err)
		}
	}
	return n, tx.Commit()
}

func hashArquivo(caminho string) (string, error) {
	f, err := os.Open(caminho)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
