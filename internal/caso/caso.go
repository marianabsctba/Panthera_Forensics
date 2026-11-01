// Package caso guarda tudo o que pertence a um caso em uma unica pasta: evidencias
// imutaveis, banco, saidas brutas e custodia. Um banco por caso isola os dados e
// permite arquivar ou entregar o caso inteiro.
package caso

import (
	"archive/zip"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marianabsctba/Panthera_Forensics/internal/custodia"
)

// Info sao os dados de identificacao do caso.
type Info struct {
	ID       string `json:"id"`
	Nome     string `json:"nome"`
	Numero   string `json:"numero"`
	Perito   string `json:"perito"`
	CriadoEm string `json:"criado_em"`
}

// Caso e um caso aberto.
type Caso struct {
	Info     Info
	Dir      string
	DB       *sql.DB
	Custodia *custodia.Registro
}

// Evidencia e um arquivo preservado no caso.
type Evidencia struct {
	ID         int64  `json:"id"`
	PaiID      *int64 `json:"pai_id,omitempty"`
	Nome       string `json:"nome"`
	Origem     string `json:"origem"`
	Tamanho    int64  `json:"tamanho"`
	SHA256     string `json:"sha256"`
	SHA1       string `json:"sha1"`
	MD5        string `json:"md5"`
	Tipo       string `json:"tipo"`
	Adicionada string `json:"adicionada"`
}

const esquema = `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS evidencias(
  id INTEGER PRIMARY KEY, pai_id INTEGER REFERENCES evidencias(id), nome TEXT NOT NULL, origem TEXT NOT NULL,
  tamanho INTEGER NOT NULL, sha256 TEXT NOT NULL, sha1 TEXT NOT NULL, md5 TEXT NOT NULL,
  tipo TEXT NOT NULL DEFAULT '', adicionada TEXT NOT NULL, UNIQUE(sha256, origem));
CREATE TABLE IF NOT EXISTS execucoes(
  id INTEGER PRIMARY KEY, chave TEXT NOT NULL, modulo TEXT NOT NULL, titulo TEXT NOT NULL, versao TEXT NOT NULL,
  ferramenta_sha256 TEXT NOT NULL DEFAULT '', args TEXT NOT NULL DEFAULT '[]', estado TEXT NOT NULL,
  inicio TEXT NOT NULL, fim TEXT, erro TEXT NOT NULL DEFAULT '', registros INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS execucoes_chave ON execucoes(chave, estado);
CREATE TABLE IF NOT EXISTS registros(
  id INTEGER PRIMARY KEY, execucao_id INTEGER NOT NULL REFERENCES execucoes(id), tipo TEXT NOT NULL,
  quando TEXT, quando_bruto TEXT NOT NULL DEFAULT '', fonte TEXT NOT NULL DEFAULT '', descricao TEXT NOT NULL,
  severidade TEXT NOT NULL DEFAULT '', origem_arquivo TEXT NOT NULL DEFAULT '', origem_local TEXT NOT NULL DEFAULT '',
  dados TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS registros_quando ON registros(quando);
CREATE INDEX IF NOT EXISTS registros_tipo ON registros(tipo, severidade);
CREATE TABLE IF NOT EXISTS entidades(
  id INTEGER PRIMARY KEY, tipo TEXT NOT NULL, valor TEXT NOT NULL COLLATE NOCASE, UNIQUE(tipo, valor));
CREATE TABLE IF NOT EXISTS registro_entidade(
  registro_id INTEGER NOT NULL REFERENCES registros(id), entidade_id INTEGER NOT NULL REFERENCES entidades(id),
  PRIMARY KEY(registro_id, entidade_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS entidade_registros ON registro_entidade(entidade_id);
CREATE VIRTUAL TABLE IF NOT EXISTS busca USING fts5(descricao, fonte, dados);
`

// Criar inicia um caso novo dentro de raiz.
func Criar(raiz, nome, numero, perito string) (*Caso, error) {
	nome = strings.TrimSpace(nome)
	if nome == "" {
		return nil, errors.New("o caso precisa de um nome")
	}
	sufixo := make([]byte, 4)
	if _, err := rand.Read(sufixo); err != nil {
		return nil, err
	}
	agora := time.Now().UTC()
	info := Info{
		ID:       agora.Format("20060102-150405") + "-" + hex.EncodeToString(sufixo),
		Nome:     nome,
		Numero:   strings.TrimSpace(numero),
		Perito:   strings.TrimSpace(perito),
		CriadoEm: agora.Format(time.RFC3339),
	}
	dir := filepath.Join(raiz, info.ID)
	if err := os.MkdirAll(filepath.Join(dir, "evidencias"), 0o755); err != nil {
		return nil, err
	}
	dados, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "caso.json"), dados, 0o644); err != nil {
		return nil, err
	}
	c, err := Abrir(dir)
	if err != nil {
		return nil, err
	}
	if _, err := c.Custodia.Registrar("caso.criado", map[string]any{"id": info.ID, "nome": info.Nome, "numero": info.Numero}); err != nil {
		c.Fechar()
		return nil, err
	}
	return c, nil
}

// Abrir abre um caso existente. Falha se a custodia tiver sido adulterada.
func Abrir(dir string) (*Caso, error) {
	dados, err := os.ReadFile(filepath.Join(dir, "caso.json"))
	if err != nil {
		return nil, err
	}
	var info Info
	if err := json.Unmarshal(dados, &info); err != nil {
		return nil, err
	}
	reg, err := custodia.Abrir(filepath.Join(dir, "custodia.jsonl"), info.Perito)
	if err != nil {
		return nil, fmt.Errorf("custodia do caso: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(dir, "caso.db"))+"?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(esquema); err != nil {
		db.Close()
		return nil, err
	}
	return &Caso{Info: info, Dir: dir, DB: db, Custodia: reg}, nil
}

// Fechar libera o banco.
func (c *Caso) Fechar() error { return c.DB.Close() }

// Listar devolve os casos de uma pasta, do mais recente ao mais antigo.
func Listar(raiz string) ([]Info, error) {
	itens, err := os.ReadDir(raiz)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	casos := []Info{}
	for i := len(itens) - 1; i >= 0; i-- {
		dados, err := os.ReadFile(filepath.Join(raiz, itens[i].Name(), "caso.json"))
		if err != nil {
			continue
		}
		var info Info
		if json.Unmarshal(dados, &info) == nil {
			casos = append(casos, info)
		}
	}
	return casos, nil
}

// CaminhoEvidencia e onde o conteudo fica guardado, pelo proprio hash.
func (c *Caso) CaminhoEvidencia(sha string) string {
	return filepath.Join(c.Dir, "evidencias", sha[:2], sha)
}

// AdicionarCaminho preserva um arquivo ou uma pasta inteira.
func (c *Caso) AdicionarCaminho(caminho string) ([]Evidencia, error) {
	info, err := os.Stat(caminho)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		f, err := os.Open(caminho)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return c.Adicionar(f, filepath.Base(caminho), caminho)
	}
	var todas []Evidencia
	err = filepath.WalkDir(caminho, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		novas, err := c.Adicionar(f, filepath.Base(p), p)
		todas = append(todas, novas...)
		return err
	})
	return todas, err
}

// Adicionar copia o conteudo para o cofre do caso, calculando os hashes durante a
// copia. Um pacote .zip e preservado inteiro e tambem aberto em evidencias filhas.
func (c *Caso) Adicionar(r io.Reader, nome, origem string) ([]Evidencia, error) {
	e, err := c.guardar(r, nome, origem, nil)
	if err != nil {
		return nil, err
	}
	todas := []Evidencia{e}
	if strings.EqualFold(filepath.Ext(nome), ".zip") {
		filhas, err := c.abrirPacote(e)
		if err != nil {
			return todas, fmt.Errorf("pacote %s: %w", nome, err)
		}
		todas = append(todas, filhas...)
	}
	return todas, nil
}

// AdicionarDerivado preserva um arquivo extraido de outra evidencia, ligado a ela.
func (c *Caso) AdicionarDerivado(r io.Reader, nome, origem string, pai int64) (Evidencia, error) {
	return c.guardar(r, nome, origem, &pai)
}

func (c *Caso) guardar(r io.Reader, nome, origem string, pai *int64) (Evidencia, error) {
	cofre := filepath.Join(c.Dir, "evidencias")
	tmp, err := os.CreateTemp(cofre, "entrada-*")
	if err != nil {
		return Evidencia{}, err
	}
	defer os.Remove(tmp.Name())
	s256, s1, m5 := sha256.New(), sha1.New(), md5.New()
	tamanho, err := io.Copy(io.MultiWriter(tmp, s256, s1, m5), r)
	if err != nil {
		tmp.Close()
		return Evidencia{}, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Evidencia{}, err
	}
	if err := tmp.Close(); err != nil {
		return Evidencia{}, err
	}
	e := Evidencia{
		PaiID: pai, Nome: nome, Origem: origem, Tamanho: tamanho,
		SHA256: hex.EncodeToString(s256.Sum(nil)), SHA1: hex.EncodeToString(s1.Sum(nil)), MD5: hex.EncodeToString(m5.Sum(nil)),
		Adicionada: time.Now().UTC().Format(time.RFC3339),
	}
	destino := c.CaminhoEvidencia(e.SHA256)
	if _, err := os.Stat(destino); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(destino), 0o755); err != nil {
			return e, err
		}
		if err := os.Rename(tmp.Name(), destino); err != nil {
			return e, err
		}
		if err := os.Chmod(destino, 0o444); err != nil {
			return e, err
		}
	}
	res, err := c.DB.Exec(`INSERT INTO evidencias(pai_id,nome,origem,tamanho,sha256,sha1,md5,adicionada) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(sha256,origem) DO NOTHING`, pai, e.Nome, e.Origem, e.Tamanho, e.SHA256, e.SHA1, e.MD5, e.Adicionada)
	if err != nil {
		return e, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		err := c.DB.QueryRow(`SELECT id FROM evidencias WHERE sha256=? AND origem=?`, e.SHA256, e.Origem).Scan(&e.ID)
		return e, err
	}
	e.ID, _ = res.LastInsertId()
	_, err = c.Custodia.Registrar("evidencia.adicionada", map[string]any{
		"evidencia": e.ID, "nome": e.Nome, "origem": e.Origem, "tamanho": e.Tamanho,
		"sha256": e.SHA256, "sha1": e.SHA1, "md5": e.MD5, "pai": pai,
	})
	return e, err
}

func (c *Caso) abrirPacote(pacote Evidencia) ([]Evidencia, error) {
	z, err := zip.OpenReader(c.CaminhoEvidencia(pacote.SHA256))
	if err != nil {
		return nil, err
	}
	defer z.Close()
	var filhas []Evidencia
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		r, err := f.Open()
		if err != nil {
			return filhas, err
		}
		// O nome vem de dentro do pacote e nao e confiavel: so serve para exibir,
		// porque o arquivo e gravado pelo proprio hash.
		interno := strings.ReplaceAll(f.Name, `\`, "/")
		id := pacote.ID
		e, err := c.guardar(r, path.Base(interno), pacote.Nome+"!"+interno, &id)
		r.Close()
		if err != nil {
			return filhas, err
		}
		filhas = append(filhas, e)
	}
	return filhas, nil
}

// Evidencias lista as evidencias do caso.
func (c *Caso) Evidencias() ([]Evidencia, error) {
	linhas, err := c.DB.Query(`SELECT id,pai_id,nome,origem,tamanho,sha256,sha1,md5,tipo,adicionada FROM evidencias ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer linhas.Close()
	todas := []Evidencia{}
	for linhas.Next() {
		var e Evidencia
		var pai sql.NullInt64
		if err := linhas.Scan(&e.ID, &pai, &e.Nome, &e.Origem, &e.Tamanho, &e.SHA256, &e.SHA1, &e.MD5, &e.Tipo, &e.Adicionada); err != nil {
			return nil, err
		}
		if pai.Valid {
			e.PaiID = &pai.Int64
		}
		todas = append(todas, e)
	}
	return todas, linhas.Err()
}

// Conferencia e o resultado de recalcular o hash de uma evidencia.
type Conferencia struct {
	Evidencia Evidencia `json:"evidencia"`
	Integra   bool      `json:"integra"`
	Problema  string    `json:"problema,omitempty"`
}

// Verificar recalcula o hash de cada evidencia e registra o resultado na custodia.
func (c *Caso) Verificar() ([]Conferencia, error) {
	todas, err := c.Evidencias()
	if err != nil {
		return nil, err
	}
	resultado := make([]Conferencia, 0, len(todas))
	integras := 0
	for _, e := range todas {
		conf := Conferencia{Evidencia: e}
		atual, err := hashArquivo(c.CaminhoEvidencia(e.SHA256))
		switch {
		case err != nil:
			conf.Problema = "arquivo ausente ou ilegível"
		case atual != e.SHA256:
			conf.Problema = "conteúdo diferente do preservado"
		default:
			conf.Integra = true
			integras++
		}
		resultado = append(resultado, conf)
	}
	_, err = c.Custodia.Registrar("evidencias.verificadas", map[string]any{"total": len(todas), "integras": integras})
	return resultado, err
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
