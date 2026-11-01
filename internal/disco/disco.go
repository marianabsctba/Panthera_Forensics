// Package disco le imagens de disco com o The Sleuth Kit e responde no contrato de
// modulos: registros.jsonl para a timeline e derivados.jsonl com os artefatos
// extraidos, que voltam ao nucleo como novas evidencias.
package disco

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
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
	Setores   int64
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

var linhaMmls = regexp.MustCompile(`^\d+:\s+\d+:\d+\s+(\d+)\s+\d+\s+(\d+)\s+(.*)$`)

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
		setores, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			continue
		}
		p = append(p, Particao{Inicio: inicio, Setores: setores, Descricao: strings.TrimSpace(m[3])})
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
	`|/(documents and settings|users)/[^/]+/.*/usrclass\.dat` +
	// Atalhos e listas de atalhos dizem o que foi aberto, inclusive em midia que ja saiu.
	`|/(documents and settings|users)/[^/]+/.+\.lnk` +
	`|/users/[^/]+/.+/automaticdestinations/[^/]+\.automaticdestinations-ms` +
	`|/\$extend/\$usnjrnl:\$j` +
	`|/(google/chrome|microsoft/edge|bravesoftware/brave-browser)/user data/[^/]+/(history|cookies|web data|bookmarks|preferences|favicons|top sites)` +
	// Executaveis fora da pasta do Windows, onde programas instalados pelo usuario ficam.
	`|/(program files[^/]*|documents and settings|users|recycler|\$recycle\.bin|temp)/.+\.(exe|dll|scr|sys)` +
	`)$`)

// textos sao arquivos pequenos de configuracao e anotacao, com conteudo util na busca.
// A pasta do Windows fica de fora: sao milhares de arquivos do proprio sistema.
var (
	textos       = regexp.MustCompile(`(?i)\.(ini|txt|log|cfg|conf|url|xml|htm|html|csv|nfo|lst)$`)
	pastaWindows = regexp.MustCompile(`(?i)^/windows/`)
	// O log de instalacao de dispositivos guarda a primeira conexao de cada USB.
	textoDoSistema = regexp.MustCompile(`(?i)^/windows/inf/setupapi\.dev(\.\d+_\d+)?\.log$`)
	notas          = regexp.MustCompile(`(?i)/sticky notes/stickynotes\.snt$`)
	// A lixeira vazia ainda guarda quem foi apagado e quando, nas entradas $I apagadas.
	lixeira = regexp.MustCompile(`(?i)/\$recycle\.bin/[^/]+/\$i[^/]*$|/recycler/[^/]+/info2$`)
)

const maximoTexto = 2 * 1024 * 1024

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

var (
	trechoUTF16 = regexp.MustCompile(`(?:[\x20-\x7e]\x00){2,}`)
	internoNota = regexp.MustCompile(`(?i)^(root entry|version|metafile|[0-9a-f]{8}-[0-9a-f-]+|\d+)$`)
)

// TextoDasNotas tira o texto de um StickyNotes.snt, um arquivo composto com cada nota
// em um fluxo proprio. O texto simples de cada nota fica em UTF-16, junto dos nomes de
// fluxo, que nao interessam.
func TextoDasNotas(b []byte) string {
	var linhas []string
	for _, trecho := range trechoUTF16.FindAll(b, -1) {
		unidades := make([]uint16, 0, len(trecho)/2)
		for i := 0; i+1 < len(trecho); i += 2 {
			unidades = append(unidades, uint16(trecho[i])|uint16(trecho[i+1])<<8)
		}
		linha := strings.TrimSpace(string(utf16.Decode(unidades)))
		if linha != "" && !internoNota.MatchString(linha) {
			linhas = append(linhas, linha)
		}
	}
	return strings.Join(linhas, "\n")
}

// registro segue o formato "contrato" dos modulos.
type registro struct {
	Tipo        string         `json:"tipo"`
	Severidade  string         `json:"severidade,omitempty"`
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
		// Uma imagem ilegivel nao pode custar o resultado das outras: ela vira um alerta e a
		// execucao termina como parcial, com tudo o que foi possivel ler.
		if err := t.imagem(segmentos); err != nil {
			nome := filepath.Base(segmentos[0])
			erros = append(erros, fmt.Errorf("%s: %w", nome, err))
			if e := t.registros.Encode(registro{
				Tipo: "alerta", Severidade: "media", Fonte: "Imagem de disco",
				Descricao:   fmt.Sprintf("Imagem não lida, examine por outro meio: %s (%v)", nome, err),
				OrigemLocal: nome,
				Dados:       map[string]any{"imagem": nome, "erro": err.Error()},
			}); e != nil {
				return e
			}
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
	motivo     string
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
	h5, h1, h256 := md5.New(), sha1.New(), sha256.New()
	var erros bytes.Buffer
	c := t.comando("img_cat", segmentos...)
	c.Stdout = io.MultiWriter(h5, h1, h256)
	c.Stderr = &erros
	if err := c.Run(); err != nil {
		return fmt.Errorf("img_cat: %w: %s", err, strings.TrimSpace(erros.String()))
	}
	md5Hex, sha1Hex, shaHex := hex.EncodeToString(h5.Sum(nil)), hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(h256.Sum(nil))
	nome := filepath.Base(segmentos[0])
	dados := map[string]any{"imagem": nome, "md5_conteudo": md5Hex, "sha1_conteudo": sha1Hex, "sha256_conteudo": shaHex, "segmentos": len(segmentos)}
	r := registro{
		Tipo: "evento", Fonte: "Imagem de disco",
		Descricao:   fmt.Sprintf("Hash do conteúdo de %s: MD5 %s, SHA-1 %s", nome, md5Hex, sha1Hex),
		OrigemLocal: nome,
		Entidades:   []entidade{{Tipo: "hash", Valor: md5Hex}, {Tipo: "hash", Valor: sha1Hex}, {Tipo: "hash", Valor: shaHex}},
		Dados:       dados,
	}
	// O E01 guarda o hash calculado na aquisicao: a comparacao mostra se a copia mudou depois.
	var informacao bytes.Buffer
	c = t.comando("img_stat", segmentos...)
	c.Stdout = &informacao
	_ = c.Run()
	if m := hashGravado.FindStringSubmatch(informacao.String()); m != nil {
		dados["md5_gravado"] = strings.ToLower(m[1])
		if strings.EqualFold(m[1], md5Hex) {
			r.Descricao += ". Confere com o hash gravado na aquisição"
		} else {
			r.Tipo, r.Severidade = "alerta", "alta"
			r.Descricao += ". NÃO confere com o hash gravado na aquisição: " + strings.ToLower(m[1])
		}
	}
	return t.registros.Encode(r)
}

var hashGravado = regexp.MustCompile(`(?i)MD5 hash of data:\s*([0-9a-f]{32})`)

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
	for _, p := range InterpretarMmls(mmls.String()) {
		if p.Setores > 0 {
			if err := t.registros.Encode(registro{
				Tipo: "evento", Fonte: "Imagem de disco",
				Descricao:   fmt.Sprintf("Partição de %s no setor %d: %d setores (%.1f GB), %s", filepath.Base(segmentos[0]), p.Inicio, p.Setores, float64(p.Setores)*512/(1<<30), p.Descricao),
				OrigemLocal: fmt.Sprintf("partição no setor %d", p.Inicio),
				Dados:       map[string]any{"imagem": filepath.Base(segmentos[0]), "inicio": p.Inicio, "setores": p.Setores, "descricao": p.Descricao},
			}); err != nil {
				return err
			}
		}
		ok, err := t.particao(segmentos, p)
		if err != nil {
			return err
		}
		if ok {
			lidas++
		} else {
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
		// Antes de desistir: CD e DVD em UDF tem leitura propria.
		otico, err := t.discoOtico(segmentos)
		if err != nil {
			return err
		}
		if otico {
			return nil
		}
		// A suspeita de criptografia vem so da entropia alta, que tambem aparece em conteudo
		// comprimido e em formatos desconhecidos.
		return fmt.Errorf("nenhum sistema de arquivos reconhecido, e isso não prova criptografia: %s", t.motivo)
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
			// Um caso pode ter varias imagens: o inode so faz sentido junto com a imagem certa.
			r.Dados["imagem"] = filepath.Base(segmentos[0])
			if err := t.registros.Encode(r); err != nil {
				return false, err
			}
		}
		if !e.Residual && !e.NomeArquivo && ((!e.Apagado && artefatos.MatchString(e.Caminho)) || lixeira.MatchString(e.Caminho)) {
			nomes = append(nomes, e)
		}
		if !e.Apagado && !e.Residual && !e.NomeArquivo && e.Tamanho > 0 && e.Tamanho <= maximoTexto &&
			(notas.MatchString(e.Caminho) || textoDoSistema.MatchString(e.Caminho) ||
				(textos.MatchString(e.Caminho) && !pastaWindows.MatchString(e.Caminho))) {
			legiveis = append(legiveis, e)
		}
	}
	if err := leitor.Err(); err != nil {
		return false, err
	}
	if err := c.Wait(); err != nil && total == 0 {
		// A mensagem da ferramenta explica o motivo, como uma suspeita de criptografia.
		t.motivo = strings.Join(strings.Fields(erros.String()), " ")
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
	if notas.MatchString(e.Caminho) {
		texto, ok = TextoDasNotas(conteudo), true
	}
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
	nome := baseNome(e.Caminho)
	// A ferramenta do diario so reconhece o fluxo pelo nome dele, sem o arquivo da frente.
	if strings.EqualFold(nome, "$UsnJrnl:$J") {
		nome = "$J"
	}
	return t.derivados.Encode(Derivado{
		Arquivo: filepath.ToSlash(relativo), Nome: nome,
		Origem: e.Caminho, Evidencia: segmentos[0],
	})
}

// escolherImagem acha os segmentos da imagem pedida. Registros antigos nao dizem a imagem:
// com mais de uma no caso, ler a primeira poderia devolver o arquivo de outro disco.
func escolherImagem(grupos [][]string, imagem string) ([]string, error) {
	if len(grupos) == 0 {
		return nil, errors.New("imagem nao encontrada")
	}
	if imagem == "" {
		if len(grupos) > 1 {
			return nil, errors.New("este registro nao diz de qual imagem veio: processe o caso de novo para abrir o arquivo")
		}
		return grupos[0], nil
	}
	for _, g := range grupos {
		if strings.EqualFold(filepath.Base(g[0]), imagem) {
			return g, nil
		}
	}
	return nil, fmt.Errorf("imagem nao encontrada: %s", imagem)
}

// LerArquivo devolve o conteudo de um arquivo de uma imagem, inclusive apagado, pelo inode
// que a leitura de disco registrou. Limite zero traz o arquivo inteiro.
func LerArquivo(dirBin, dirEntrada, imagem string, particao int64, inode string, limite int64) ([]byte, error) {
	grupos, err := Agrupar(dirEntrada)
	if err != nil {
		return nil, err
	}
	segmentos, err := escolherImagem(grupos, imagem)
	if err != nil {
		return nil, err
	}
	t := &trabalho{bin: dirBin}
	args := append([]string{"-o", strconv.FormatInt(particao, 10)}, segmentos...)
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
