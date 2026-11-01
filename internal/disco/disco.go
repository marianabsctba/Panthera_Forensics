// Package disco le imagens de disco com o The Sleuth Kit e responde no contrato de
// modulos: registros.jsonl para a timeline e derivados.jsonl com os artefatos
// extraidos, que voltam ao nucleo como novas evidencias.
package disco

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/marianabsctba/Panthera_Forensics/internal/processo"
)

// Particao e um trecho da imagem que pode conter um sistema de arquivos.
type Particao struct {
	Inicio    int64
	Descricao string
}

// Entrada e uma linha do formato body do fls.
type Entrada struct {
	Caminho     string
	Inode       string
	Modo        string
	Tamanho     int64
	Acesso      int64
	Alteracao   int64
	Mudanca     int64
	Criacao     int64
	Apagado     bool
	Residual    bool
	NomeArquivo bool
}

var linhaMmls = regexp.MustCompile(`^\d+:\s+\d+:\d+\s+(\d+)\s+\d+\s+\d+\s+(.*)$`)

// InterpretarMmls devolve as particoes alocadas. Sem tabela de particoes, a imagem
// inteira e tratada como um unico volume.
func InterpretarMmls(saida string) []Particao {
	var p []Particao
	for _, linha := range strings.Split(saida, "\n") {
		m := linhaMmls.FindStringSubmatch(strings.TrimSpace(linha))
		if m == nil {
			continue
		}
		inicio, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			continue
		}
		p = append(p, Particao{Inicio: inicio, Descricao: strings.TrimSpace(m[2])})
	}
	if len(p) == 0 {
		return []Particao{{Inicio: 0, Descricao: "volume sem tabela de partições"}}
	}
	return p
}

// InterpretarBody le uma linha do fls -m. O nome pode conter |, entao os campos sao
// contados a partir das duas pontas.
func InterpretarBody(linha string) (Entrada, bool) {
	c := strings.Split(linha, "|")
	if len(c) < 11 {
		return Entrada{}, false
	}
	fim := c[len(c)-9:]
	e := Entrada{Caminho: strings.Join(c[1:len(c)-9], "|"), Inode: fim[0], Modo: fim[1]}
	numeros := []*int64{&e.Tamanho, &e.Acesso, &e.Alteracao, &e.Mudanca, &e.Criacao}
	for i, n := range numeros {
		v, err := strconv.ParseInt(fim[4+i], 10, 64)
		if err != nil {
			return Entrada{}, false
		}
		*n = v
	}
	switch {
	case strings.HasSuffix(e.Caminho, " (deleted-realloc)"):
		// A entrada de metadados ja pertence a outro arquivo: as datas nao sao deste nome.
		e.Caminho = strings.TrimSuffix(e.Caminho, " (deleted-realloc)")
		e.Residual = true
	case strings.HasSuffix(e.Caminho, " (deleted)"):
		e.Caminho = strings.TrimSuffix(e.Caminho, " (deleted)")
		e.Apagado = true
		// Inode 0 e so um nome que sobrou no diretorio. No DFR-01 do NIST, isso acontece
		// com um arquivo que continua ativo.
		if e.Inode == "0" {
			e.Apagado, e.Residual = false, true
		}
	}
	if strings.HasSuffix(e.Caminho, " ($FILE_NAME)") {
		e.Caminho = strings.TrimSuffix(e.Caminho, " ($FILE_NAME)")
		e.NomeArquivo = true
	}
	return e, true
}

// artefatos sao os arquivos ativos que seguem para outros modulos.
var artefatos = regexp.MustCompile(`(?i)(` +
	`/windows/(system32/winevt/logs/[^/]+\.evtx|prefetch/[^/]+\.pf|system32/config/(software|system|sam|security))` +
	`|/(documents and settings|users)/[^/]+/ntuser\.dat` +
	`|/(google/chrome|microsoft/edge|bravesoftware/brave-browser)/user data/[^/]+/(history|cookies|web data|bookmarks|preferences|favicons|top sites)` +
	// Executaveis fora da pasta do Windows, onde programas instalados pelo usuario ficam.
	`|/(program files[^/]*|documents and settings|users|recycler|\$recycle\.bin|temp)/.+\.(exe|dll|scr|sys)` +
	`)$`)

// textos sao arquivos pequenos de configuracao e anotacao, com conteudo util na busca.
// A pasta do Windows fica de fora: sao milhares de arquivos do proprio sistema.
var (
	textos       = regexp.MustCompile(`(?i)\.(ini|txt|log|cfg|conf|url|xml|htm|html|csv|nfo|lst)$`)
	pastaWindows = regexp.MustCompile(`(?i)^/windows/`)
)

const maximoTexto = 256 * 1024

// TextoLegivel converte o conteudo em texto, ou diz que e binario. Aceita UTF-16, comum
// em arquivos do Windows, e Latin-1, comum nos antigos.
func TextoLegivel(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		unidades := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			unidades = append(unidades, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(unidades)), true
	}
	controle := 0
	for _, c := range b {
		if c < 9 || (c > 13 && c < 32) {
			controle++
		}
	}
	if controle*20 > len(b) {
		return "", false
	}
	if utf8.Valid(b) {
		return string(b), true
	}
	runas := make([]rune, len(b))
	for i, c := range b {
		runas[i] = rune(c)
	}
	return string(runas), true
}

// registro segue o formato "contrato" dos modulos.
type registro struct {
	Tipo        string         `json:"tipo"`
	Quando      string         `json:"quando,omitempty"`
	Fonte       string         `json:"fonte"`
	Descricao   string         `json:"descricao"`
	OrigemLocal string         `json:"origem_local"`
	Entidades   []entidade     `json:"entidades,omitempty"`
	Dados       map[string]any `json:"dados"`
}

type entidade struct {
	Tipo  string `json:"tipo"`
	Valor string `json:"valor"`
}

// Derivado descreve um arquivo extraido de uma evidencia.
type Derivado struct {
	Arquivo   string `json:"arquivo"`
	Nome      string `json:"nome"`
	Origem    string `json:"origem"`
	Evidencia string `json:"evidencia"`
}

func hora(segundos int64) string {
	if segundos <= 0 {
		return ""
	}
	return time.Unix(segundos, 0).UTC().Format(time.RFC3339)
}

// Registros transforma uma entrada em registros da timeline. O nucleo guarda a saida
// bruta do fls, entao as datas de $FILE_NAME continuam disponiveis ao perito.
func Registros(e Entrada, inicio int64) []registro {
	if e.NomeArquivo {
		return nil
	}
	local := fmt.Sprintf("partição no setor %d, inode %s", inicio, e.Inode)
	dados := map[string]any{
		"caminho": e.Caminho, "inode": e.Inode, "modo": e.Modo, "tamanho": e.Tamanho, "particao": inicio,
		"apagado": e.Apagado, "residual": e.Residual,
		"acesso": hora(e.Acesso), "alteracao": hora(e.Alteracao), "mudanca": hora(e.Mudanca), "criacao": hora(e.Criacao),
	}
	novo := func(quando, descricao string) registro {
		r := registro{Tipo: "evento", Quando: quando, Fonte: "Sistema de arquivos", Descricao: descricao, OrigemLocal: local, Dados: dados}
		if nome := baseNome(e.Caminho); nome != "" {
			r.Entidades = []entidade{{Tipo: "arquivo", Valor: nome}}
		}
		return r
	}
	if e.Residual {
		return []registro{novo("", "Nome residual em diretório, sem dados confiáveis do arquivo: "+e.Caminho)}
	}
	var saida []registro
	for _, d := range []struct {
		quando int64
		texto  string
	}{{e.Criacao, "Arquivo criado"}, {e.Alteracao, "Arquivo alterado"}, {e.Acesso, "Arquivo acessado"}} {
		if q := hora(d.quando); q != "" {
			saida = append(saida, novo(q, d.texto+": "+e.Caminho))
		}
	}
	if e.Apagado {
		// O sistema de arquivos nao guarda a hora da exclusao.
		saida = append(saida, novo(hora(e.Mudanca), "Arquivo apagado em momento desconhecido; esta é a última mudança antes disso: "+e.Caminho))
	}
	return saida
}

func baseNome(caminho string) string {
	return caminho[strings.LastIndex(caminho, "/")+1:]
}

// Executar processa todas as imagens de uma pasta de entrada.
func Executar(dirBin, dirEntrada, dirSaida string) error {
	grupos, err := Agrupar(dirEntrada)
	if err != nil {
		return err
	}
	registros, err := os.Create(filepath.Join(dirSaida, "registros.jsonl"))
	if err != nil {
		return err
	}
	defer registros.Close()
	derivados, err := os.Create(filepath.Join(dirSaida, "derivados.jsonl"))
	if err != nil {
		return err
	}
	defer derivados.Close()
	saidaRegistros := bufio.NewWriter(registros)
	saidaDerivados := bufio.NewWriter(derivados)
	t := &trabalho{bin: dirBin, saida: dirSaida, registros: json.NewEncoder(saidaRegistros), derivados: json.NewEncoder(saidaDerivados)}
	// Sem escapar & e <: o caminho precisa continuar igual ao que esta no disco.
	t.registros.SetEscapeHTML(false)
	var erros []error
	for _, segmentos := range grupos {
		if err := t.imagem(segmentos); err != nil {
			erros = append(erros, fmt.Errorf("%s: %w", filepath.Base(segmentos[0]), err))
		}
	}
	if err := saidaRegistros.Flush(); err != nil {
		return err
	}
	if err := saidaDerivados.Flush(); err != nil {
		return err
	}
	return errors.Join(erros...)
}

var segmento = regexp.MustCompile(`(?i)^(.*)\.(e\d{2}|\d{3})$`)

// Agrupar junta os segmentos de uma mesma imagem, como disco.E01 e disco.E02.
func Agrupar(dir string) ([][]string, error) {
	porNome := map[string][]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		chave := strings.ToLower(d.Name())
		if m := segmento.FindStringSubmatch(d.Name()); m != nil {
			chave = strings.ToLower(m[1]) + "|segmentos"
		}
		porNome[chave] = append(porNome[chave], p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	chaves := make([]string, 0, len(porNome))
	for k := range porNome {
		chaves = append(chaves, k)
	}
	sort.Strings(chaves)
	grupos := make([][]string, 0, len(chaves))
	for _, k := range chaves {
		g := porNome[k]
		sort.Slice(g, func(i, j int) bool {
			return strings.ToLower(filepath.Base(g[i])) < strings.ToLower(filepath.Base(g[j]))
		})
		grupos = append(grupos, g)
	}
	return grupos, nil
}

type trabalho struct {
	bin, saida string
	registros  *json.Encoder
	derivados  *json.Encoder
	extraidos  int
}

func (t *trabalho) comando(nome string, args ...string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		nome += ".exe"
	}
	return processo.Ocultar(exec.Command(filepath.Join(t.bin, nome), args...))
}

// hashConteudo calcula o hash dos dados do disco, e nao dos arquivos da imagem: um E01
// comprimido so pode ser comparado com a aquisicao original depois de lido por dentro.
func (t *trabalho) hashConteudo(segmentos []string) error {
	h5, h256 := md5.New(), sha256.New()
	var erros bytes.Buffer
	c := t.comando("img_cat", segmentos...)
	c.Stdout = io.MultiWriter(h5, h256)
	c.Stderr = &erros
	if err := c.Run(); err != nil {
		return fmt.Errorf("img_cat: %w: %s", err, strings.TrimSpace(erros.String()))
	}
	md5Hex, shaHex := hex.EncodeToString(h5.Sum(nil)), hex.EncodeToString(h256.Sum(nil))
	return t.registros.Encode(registro{
		Tipo: "evento", Fonte: "Imagem de disco",
		Descricao:   "Hash do conteúdo da imagem: MD5 " + md5Hex,
		OrigemLocal: "imagem inteira",
		Entidades:   []entidade{{Tipo: "hash", Valor: md5Hex}, {Tipo: "hash", Valor: shaHex}},
		Dados:       map[string]any{"md5_conteudo": md5Hex, "sha256_conteudo": shaHex, "segmentos": len(segmentos)},
	})
}

func (t *trabalho) imagem(segmentos []string) error {
	if err := t.hashConteudo(segmentos); err != nil {
		return err
	}
	// mmls termina com erro quando nao ha tabela de particoes, e isso nao e uma falha.
	var mmls bytes.Buffer
	c := t.comando("mmls", segmentos...)
	c.Stdout = &mmls
	_ = c.Run()
	lidas := 0
	var erros []string
	for _, p := range InterpretarMmls(mmls.String()) {
		ok, err := t.particao(segmentos, p)
		if err != nil {
			return err
		}
		if ok {
			lidas++
		} else {
			erros = append(erros, p.Descricao)
			if err := t.registros.Encode(registro{
				Tipo: "evento", Fonte: "Sistema de arquivos",
				Descricao:   fmt.Sprintf("Partição no setor %d não pôde ser lida: %s", p.Inicio, p.Descricao),
				OrigemLocal: fmt.Sprintf("partição no setor %d", p.Inicio),
				Dados:       map[string]any{"particao": p.Inicio, "descricao": p.Descricao},
			}); err != nil {
				return err
			}
		}
	}
	if lidas == 0 {
		return fmt.Errorf("nenhum sistema de arquivos reconhecido (%s)", strings.Join(erros, "; "))
	}
	return nil
}

// particao devolve false quando o fls nao reconhece um sistema de arquivos ali, o que
// e normal em areas como swap e particoes de recuperacao.
func (t *trabalho) particao(segmentos []string, p Particao) (bool, error) {
	args := append([]string{"-r", "-m", "/", "-o", strconv.FormatInt(p.Inicio, 10)}, segmentos...)
	bruto, err := os.Create(filepath.Join(t.saida, fmt.Sprintf("fls-%d.body", p.Inicio)))
	if err != nil {
		return false, err
	}
	defer bruto.Close()
	c := t.comando("fls", args...)
	var erros bytes.Buffer
	c.Stderr = &erros
	tubo, err := c.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err := c.Start(); err != nil {
		return false, err
	}
	vistas := map[string]bool{}
	var nomes, legiveis []Entrada
	leitor := bufio.NewScanner(tubo)
	leitor.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	total := 0
	for leitor.Scan() {
		linha := leitor.Text()
		if _, err := fmt.Fprintln(bruto, linha); err != nil {
			return false, err
		}
		e, ok := InterpretarBody(linha)
		if !ok {
			continue
		}
		total++
		// O fls pode listar a mesma entrada mais de uma vez em um percurso recursivo.
		chave := e.Caminho + "|" + e.Inode + "|" + strconv.FormatBool(e.NomeArquivo) + "|" + strconv.FormatBool(e.Apagado)
		if vistas[chave] {
			continue
		}
		vistas[chave] = true
		for _, r := range Registros(e, p.Inicio) {
			if err := t.registros.Encode(r); err != nil {
				return false, err
			}
		}
		if !e.Apagado && !e.Residual && !e.NomeArquivo && artefatos.MatchString(e.Caminho) {
			nomes = append(nomes, e)
		}
		if !e.Apagado && !e.Residual && !e.NomeArquivo && e.Tamanho > 0 && e.Tamanho <= maximoTexto &&
			textos.MatchString(e.Caminho) && !pastaWindows.MatchString(e.Caminho) {
			legiveis = append(legiveis, e)
		}
	}
	if err := leitor.Err(); err != nil {
		return false, err
	}
	if err := c.Wait(); err != nil && total == 0 {
		return false, nil
	}
	for _, e := range legiveis {
		if err := t.indexarTexto(segmentos, p, e); err != nil {
			return false, err
		}
	}
	for _, e := range nomes {
		if err := t.extrair(segmentos, p, e); err != nil {
			// Um arquivo que nao sai, por antivirus ou dano no disco, nao pode impedir os
			// outros. Ele vira um registro visivel na timeline.
			if err := t.registros.Encode(registro{
				Tipo: "evento", Fonte: "Imagem de disco",
				Descricao:   "Arquivo não extraído: " + e.Caminho + " (" + err.Error() + ")",
				OrigemLocal: fmt.Sprintf("partição no setor %d, inode %s", p.Inicio, e.Inode),
				Dados:       map[string]any{"caminho": e.Caminho, "erro": err.Error()},
			}); err != nil {
				return false, err
			}
		}
	}
	return true, nil
}

// indexarTexto coloca o conteudo de um arquivo pequeno na busca do caso. Um arquivo
// ilegivel nao atrapalha os demais: ele continua listado pelo nome.
func (t *trabalho) indexarTexto(segmentos []string, p Particao, e Entrada) error {
	args := append([]string{"-o", strconv.FormatInt(p.Inicio, 10)}, segmentos...)
	conteudo, err := t.comando("icat", append(args, e.Inode)...).Output()
	if err != nil {
		return nil
	}
	texto, ok := TextoLegivel(conteudo)
	if !ok {
		return nil
	}
	return t.registros.Encode(registro{
		Tipo: "evento", Quando: hora(e.Alteracao), Fonte: "Conteúdo de arquivo",
		Descricao:   "Texto do arquivo: " + e.Caminho,
		OrigemLocal: fmt.Sprintf("partição no setor %d, inode %s", p.Inicio, e.Inode),
		Dados:       map[string]any{"caminho": e.Caminho, "texto": texto},
	})
}

func (t *trabalho) extrair(segmentos []string, p Particao, e Entrada) error {
	t.extraidos++
	relativo := filepath.Join("derivados", strconv.Itoa(t.extraidos))
	destino := filepath.Join(t.saida, relativo)
	if err := os.MkdirAll(filepath.Dir(destino), 0o755); err != nil {
		return err
	}
	f, err := os.Create(destino)
	if err != nil {
		return err
	}
	defer f.Close()
	args := append([]string{"-o", strconv.FormatInt(p.Inicio, 10)}, segmentos...)
	c := t.comando("icat", append(args, e.Inode)...)
	c.Stdout = f
	if err := c.Run(); err != nil {
		return err
	}
	return t.derivados.Encode(Derivado{
		Arquivo: filepath.ToSlash(relativo), Nome: baseNome(e.Caminho),
		Origem: e.Caminho, Evidencia: segmentos[0],
	})
}

// LerArquivo devolve o conteudo de um arquivo de uma imagem, inclusive apagado, pelo inode
// que a leitura de disco registrou. Limite zero traz o arquivo inteiro.
func LerArquivo(dirBin, dirEntrada string, particao int64, inode string, limite int64) ([]byte, error) {
	grupos, err := Agrupar(dirEntrada)
	if err != nil {
		return nil, err
	}
	if len(grupos) == 0 {
		return nil, errors.New("imagem nao encontrada")
	}
	t := &trabalho{bin: dirBin}
	args := append([]string{"-o", strconv.FormatInt(particao, 10)}, grupos[0]...)
	c := t.comando("icat", append(args, inode)...)
	tubo, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	var leitor io.Reader = tubo
	if limite > 0 {
		leitor = io.LimitReader(tubo, limite)
	}
	conteudo, err := io.ReadAll(leitor)
	if limite > 0 {
		// O restante nao interessa: nao precisa esperar o fim de um arquivo enorme.
		_ = c.Process.Kill()
	}
	_ = c.Wait()
	return conteudo, err
}

// Hexadecimal mostra o inicio de um arquivo binario para leitura na tela.
func Hexadecimal(b []byte, limite int) string {
	if len(b) > limite {
		b = b[:limite]
	}
	return hex.Dump(b)
}
