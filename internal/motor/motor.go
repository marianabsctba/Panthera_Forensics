// Package motor identifica evidencias, monta o plano a partir dos manifestos e
// executa os modulos como processos separados. Nada aqui conhece uma ferramenta.
package motor

import (
	"bufio"
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
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
	"github.com/marianabsctba/Panthera_Forensics/internal/normaliza"
	"github.com/marianabsctba/Panthera_Forensics/internal/processo"
)

// Motor executa modulos sobre casos.
type Motor struct {
	Modulos        []*modulo.Manifesto
	DirFerramentas string
	TempoMaximo    time.Duration
	// Nucleo e o executavel usado por modulos com exec "{nucleo}". Vazio usa o atual.
	Nucleo string
	// RefazerFalhas tenta de novo o que ja falhou, por exemplo depois de ajustar o antivirus.
	RefazerFalhas bool
	// Profundo inclui os modulos opcionais, mais pesados, na analise.
	Profundo bool

	verificados sync.Map
}

// Variante cria um motor so para um pedido, sem mudar o que os outros casos usam.
func (m *Motor) Variante(refazer, profundo bool) *Motor {
	return &Motor{
		Modulos: m.Modulos, DirFerramentas: m.DirFerramentas, TempoMaximo: m.TempoMaximo,
		Nucleo: m.Nucleo, RefazerFalhas: refazer, Profundo: profundo,
	}
}

// maximoRodadas limita a cadeia de derivados: uma evidencia que gera outra que gera
// outra nao pode prender o processamento para sempre.
const maximoRodadas = 5

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
			// Um arquivo bloqueado ou removido, em geral pelo antivirus, nao pode parar os demais.
			// Ele fica sem leitura e vira um alerta na listagem de preservados.
			if _, err := os.Stat(c.CaminhoEvidencia(e.SHA256)); err != nil || !legivel(c.CaminhoEvidencia(e.SHA256)) {
				res.SemModulo++
				continue
			}
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
		if md.Opcional && !m.Profundo {
			continue
		}
		var entradas []caso.Evidencia
		for _, tipo := range md.Consome {
			for _, e := range porTipo[tipo] {
				if !md.IgnorarDerivados || e.PaiID == nil {
					entradas = append(entradas, e)
				}
			}
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
		if md.Modo == "imagem" {
			for _, grupo := range agruparSegmentos(unicas(entradas)) {
				tarefas = append(tarefas, Tarefa{Modulo: md, Entradas: grupo})
			}
			continue
		}
		if md.Modo == "pasta" {
			for _, e := range unicas(entradas) {
				tarefas = append(tarefas, Tarefa{Modulo: md, Entradas: mesmaPasta(e, evidencias)})
			}
			continue
		}
		for _, e := range unicas(entradas) {
			tarefas = append(tarefas, Tarefa{Modulo: md, Entradas: []caso.Evidencia{e}})
		}
	}
	return tarefas, res, nil
}

var numeroVersao = regexp.MustCompile(`\d+\.\d+|version \d+`)

var segmentoImagem = regexp.MustCompile(`(?i)^(.*)\.(e\d{2}|\d{3})$`)

// agruparSegmentos junta as partes de uma mesma imagem, como disco.E01 e disco.E02. A
// primeira parte vem primeiro, porque e por ela que as ferramentas abrem o conjunto.
func agruparSegmentos(todas []caso.Evidencia) [][]caso.Evidencia {
	porNome := map[string][]caso.Evidencia{}
	var ordem []string
	for _, e := range todas {
		chave := strings.ToLower(e.Nome)
		if m := segmentoImagem.FindStringSubmatch(e.Nome); m != nil {
			chave = strings.ToLower(m[1]) + "|segmentos"
		}
		if _, existe := porNome[chave]; !existe {
			ordem = append(ordem, chave)
		}
		porNome[chave] = append(porNome[chave], e)
	}
	grupos := make([][]caso.Evidencia, 0, len(ordem))
	for _, chave := range ordem {
		g := porNome[chave]
		sort.Slice(g, func(i, j int) bool { return strings.ToLower(g[i].Nome) < strings.ToLower(g[j].Nome) })
		grupos = append(grupos, g)
	}
	return grupos
}

// caminhoWSL converte D:\pasta em /mnt/d/pasta, para ferramentas no ambiente Linux.
func caminhoWSL(caminho string) string {
	limpo := filepath.ToSlash(caminho)
	if len(limpo) >= 2 && limpo[1] == ':' {
		return "/mnt/" + strings.ToLower(limpo[:1]) + limpo[2:]
	}
	return limpo
}

// mesmaPasta junta um arquivo aos que vieram da mesma pasta de origem, para ferramentas
// que leem um conjunto, como o perfil inteiro de um navegador. O arquivo vem primeiro.
func mesmaPasta(e caso.Evidencia, todas []caso.Evidencia) []caso.Evidencia {
	grupo := []caso.Evidencia{e}
	nomes := map[string]bool{strings.ToLower(e.Nome): true}
	for _, o := range todas {
		if o.ID != e.ID && !nomes[strings.ToLower(o.Nome)] && pastaOrigem(o.Origem) == pastaOrigem(e.Origem) {
			nomes[strings.ToLower(o.Nome)] = true
			grupo = append(grupo, o)
		}
	}
	return grupo
}

func pastaOrigem(origem string) string {
	limpo := strings.ReplaceAll(origem, `\`, "/")
	if i := strings.LastIndex(limpo, "/"); i >= 0 {
		return strings.ToLower(limpo[:i])
	}
	return ""
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
	var res Resultado
	ausentes := map[string]bool{}
	falhadas := map[string]bool{}
	tratadas := map[string]bool{}
	feitas := 0
	// Cada rodada pode gerar novas evidencias, como os logs extraidos de uma imagem de
	// disco, que precisam ser planejadas de novo.
	for rodada := 0; rodada < maximoRodadas; rodada++ {
		tarefas, plano, err := m.Planejar(c)
		if err != nil {
			return res, err
		}
		res.SemModulo = plano.SemModulo
		for _, titulo := range plano.Ausentes {
			if ausentes[titulo] {
				continue
			}
			ausentes[titulo] = true
			res.Ausentes = append(res.Ausentes, titulo)
			if _, err := c.Custodia.Registrar("modulo.nao_executado", map[string]any{"modulo": titulo, "motivo": "não instalado neste sistema"}); err != nil {
				return res, err
			}
		}
		executadas := 0
		// So entra no plano da rodada o que ainda nao foi tratado nesta execucao.
		var pendentes []Tarefa
		for _, t := range tarefas {
			if id := identificarTarefa(t); !falhadas[id] && !tratadas[id] {
				pendentes = append(pendentes, t)
			}
		}
		total := feitas + len(pendentes)
		for _, t := range pendentes {
			if err := ctx.Err(); err != nil {
				return res, err
			}
			id := identificarTarefa(t)
			tratadas[id] = true
			if avisar != nil {
				avisar(t.Modulo.Titulo, feitas, total)
			}
			reutilizada, err := m.Executar(ctx, c, t)
			switch {
			case err != nil:
				falhadas[id] = true
				res.Falhas = append(res.Falhas, t.Modulo.Titulo+": "+err.Error())
			case reutilizada:
				// Nas rodadas seguintes, tarefa ja feita nao e reaproveitamento: e so a
				// mesma tarefa aparecendo de novo no plano.
				if rodada == 0 {
					res.Reutilizadas++
				}
			default:
				res.Executadas++
				executadas++
				feitas++
			}
		}
		if executadas == 0 {
			break
		}
	}
	if avisar != nil {
		avisar("Listando arquivos sem leitura própria", feitas, feitas+1)
	}
	if _, err := m.listarPreservados(ctx, c); err != nil {
		return res, err
	}
	if avisar != nil {
		avisar("", feitas, feitas)
	}
	return res, nil
}

// legivel confere se o arquivo abre, porque o antivirus pode bloquear a abertura.
func legivel(caminho string) bool {
	f, err := os.Open(caminho)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func identificarTarefa(t Tarefa) string {
	partes := []string{t.Modulo.Nome}
	for _, e := range t.Entradas {
		partes = append(partes, e.SHA256)
	}
	return strings.Join(partes, "|")
}

// localizar encontra o executavel declarado. O caminho e relativo a ferramenta
// instalada ou, sem instalacao, a pasta do modulo, e aceita curinga.
func (m *Motor) localizar(md *modulo.Manifesto) (ferramenta, error) {
	cmd, ok := md.ComandoAtual()
	if !ok {
		return ferramenta{}, errors.New("modulo nao roda neste sistema")
	}
	dir := filepath.Join(m.DirFerramentas, md.Ferramenta, md.Versao)
	_, temPacote := md.PacoteAtual()
	if !temPacote && md.Dir != "" {
		dir = md.Dir
	}
	if cmd.Sistema {
		exe, err := exec.LookPath(cmd.Exec)
		if err != nil {
			return ferramenta{}, err
		}
		if len(cmd.Verificar) > 0 {
			if _, visto := m.verificados.Load(md.Nome); !visto {
				if err := processo.Ocultar(exec.Command(exe, cmd.Verificar...)).Run(); err != nil {
					return ferramenta{}, fmt.Errorf("%s indisponivel: %w", md.Nome, err)
				}
				m.verificados.Store(md.Nome, true)
			}
		}
		return ferramenta{dir: dir, exec: exe}, nil
	}
	if cmd.Exec == "{nucleo}" {
		if temPacote {
			if _, err := os.Stat(filepath.Join(dir, ".instalado")); err != nil {
				return ferramenta{}, fmt.Errorf("%s nao instalado", md.Ferramenta)
			}
		}
		exe := m.Nucleo
		if exe == "" {
			var err error
			if exe, err = os.Executable(); err != nil {
				return ferramenta{}, err
			}
		}
		return ferramenta{dir: dir, exec: exe}, nil
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
	versao := md.Versao
	if len(comando.Versao) > 0 {
		// Sem hash fixado, a versao real e o que identifica a ferramenta usada.
		saida, err := processo.Ocultar(exec.CommandContext(ctx, fer.exec, comando.Versao...)).CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("ao consultar a versao: %w", err)
		}
		// Avisos podem vir antes: vale a primeira linha com cara de numero de versao.
		versao = ""
		for _, linha := range strings.Split(string(saida), "\n") {
			if numeroVersao.MatchString(linha) {
				versao = strings.TrimSpace(linha)
				break
			}
		}
		if versao == "" {
			return false, errors.New("versao da ferramenta nao identificada")
		}
		shaFerramenta += " " + versao
	}
	dirRegras := filepath.Join(filepath.Dir(m.DirFerramentas), "regras")
	if slices.ContainsFunc(comando.Args, func(a string) bool { return strings.Contains(a, "{regras}") }) {
		// Regra diferente e analise diferente: entra na identidade da tarefa e na custodia.
		sha, err := hashPasta(filepath.Join(dirRegras, md.Nome))
		if err != nil {
			return false, err
		}
		shaFerramenta += " regras:" + sha
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

	// A mesma entrada com a mesma ferramenta tende a falhar igual: repetir so duplicaria
	// o erro a cada evidencia nova. Tentar de novo e uma decisao de quem esta no caso.
	if !m.RefazerFalhas {
		var erroAnterior string
		err = c.DB.QueryRow(`SELECT erro FROM execucoes WHERE chave=? AND estado='falhou' ORDER BY id DESC LIMIT 1`, chave).Scan(&erroAnterior)
		if err == nil {
			return false, errors.New(erroAnterior)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}

	inicio := time.Now().UTC().Format(time.RFC3339)
	res, err := c.DB.Exec(`INSERT INTO execucoes(chave,modulo,titulo,versao,ferramenta_sha256,args,estado,inicio) VALUES(?,?,?,?,?,?,?,?)`,
		chave, md.Nome, md.Titulo, versao, shaFerramenta, "[]", "rodando", inicio)
	if err != nil {
		return false, err
	}
	id, _ := res.LastInsertId()
	dirExec := filepath.Join(c.Dir, "execucoes", fmt.Sprint(id))
	dirEntrada, dirSaida := filepath.Join(dirExec, "entrada"), filepath.Join(dirExec, "saida")
	if err := os.MkdirAll(dirSaida, 0o755); err != nil {
		return false, m.falhar(c, id, md, err)
	}
	entrada, origens, err := prepararEntrada(c, dirEntrada, md.Modo, t.Entradas)
	if err != nil {
		return false, m.falhar(c, id, md, err)
	}
	args := expandirArgs(comando.Args, map[string]string{
		"{entrada}": entrada, "{saida}": dirSaida, "{ferramenta}": fer.dir,
		"{regras}": dirRegras, "{regras_wsl}": caminhoWSL(dirRegras),
		"{entrada_wsl}": caminhoWSL(entrada), "{saida_wsl}": caminhoWSL(dirSaida), "{ferramenta_wsl}": caminhoWSL(fer.dir),
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
	parcial := ""
	if err := m.rodar(ctx, fer.exec, args, dirTrabalho, arquivoSaida, filepath.Join(dirExec, "stderr.log")); err != nil {
		// Pode nao haver nada a aproveitar: uma captura cortada sem nenhum pedido ainda e
		// uma leitura parcial, e o aviso com a mensagem da ferramenta aparece na tela.
		if !comando.ParcialAceita || ctx.Err() != nil {
			return false, m.falhar(c, id, md, err)
		}
		parcial = "leitura parcial: " + ultimaLinha(filepath.Join(dirExec, "stderr.log"))
	}
	for _, padrao := range md.Saida.Derivar {
		achados, err := filepath.Glob(filepath.Join(dirSaida, filepath.FromSlash(padrao)))
		if err != nil {
			return false, m.falhar(c, id, md, err)
		}
		for _, caminho := range achados {
			nome := filepath.Base(caminho)
			if err := guardarDerivado(c, caminho, nome, t.Entradas[0].Nome+"!"+md.Nome+"/"+nome, t.Entradas[0].ID); err != nil {
				return false, m.falhar(c, id, md, fmt.Errorf("ao guardar arquivos extraidos: %w", err))
			}
		}
	}
	if md.Saida.Derivados != "" {
		if err := guardarDerivados(c, filepath.Join(dirSaida, filepath.FromSlash(md.Saida.Derivados)), dirSaida, origens); err != nil {
			return false, m.falhar(c, id, md, fmt.Errorf("ao guardar arquivos extraidos: %w", err))
		}
	}
	n, err := importar(c, id, md, dirSaida, origens)
	if err != nil {
		return false, m.falhar(c, id, md, fmt.Errorf("ao ler a saida: %w", err))
	}
	fim := time.Now().UTC().Format(time.RFC3339)
	if _, err := c.DB.Exec(`UPDATE execucoes SET estado='concluida',fim=?,registros=?,erro=? WHERE id=?`, fim, n, parcial, id); err != nil {
		return false, err
	}
	shas := make([]string, 0, len(t.Entradas))
	for _, e := range t.Entradas {
		shas = append(shas, e.SHA256)
	}
	_, err = c.Custodia.Registrar("modulo.executado", map[string]any{
		"execucao": id, "modulo": md.Nome, "versao": versao, "ferramenta_sha256": shaFerramenta,
		"args": args, "entradas": shas, "registros": n, "parcial": parcial,
	})
	return false, err
}

func ultimaLinha(caminho string) string {
	dados, err := os.ReadFile(caminho)
	if err != nil {
		return "erro da ferramenta"
	}
	linhas := strings.Split(strings.TrimSpace(string(dados)), "\n")
	linha := strings.TrimSpace(linhas[len(linhas)-1])
	if len(linha) > 300 {
		linha = linha[:300]
	}
	return linha
}

func (m *Motor) falhar(c *caso.Caso, id int64, md *modulo.Manifesto, causa error) error {
	causa = caso.ExplicarAntivirus(causa)
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
	cmd := processo.Ocultar(exec.CommandContext(ctx, executavel, args...))
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
func prepararEntrada(c *caso.Caso, dir, modo string, entradas []caso.Evidencia) (string, *origens, error) {
	var ultimo string
	o := &origens{porCaminho: map[string]string{}, evidencias: map[string]caso.Evidencia{}}
	for i, e := range entradas {
		sub := filepath.Join(dir, fmt.Sprint(i))
		if modo == "pasta" || modo == "imagem" {
			sub = dir
		}
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return "", nil, err
		}
		ultimo = filepath.Join(sub, nomeSeguro(e.Nome))
		if err := os.Link(c.CaminhoEvidencia(e.SHA256), ultimo); err != nil {
			return "", nil, err
		}
		o.unica = fmt.Sprintf("%s (evidência %d)", e.Nome, e.ID)
		o.porCaminho[normalizarCaminho(ultimo)] = o.unica
		o.evidencias[normalizarCaminho(ultimo)] = e
	}
	if len(entradas) != 1 {
		o.unica = ""
	}
	if modo == "lote" || modo == "pasta" {
		return dir, o, nil
	}
	if modo == "imagem" {
		return filepath.Join(dir, nomeSeguro(entradas[0].Nome)), o, nil
	}
	return ultimo, o, nil
}

// guardarDerivados le o JSONL do modulo e preserva cada arquivo como nova evidencia,
// ligada a evidencia de onde saiu.
func guardarDerivados(c *caso.Caso, lista, dirSaida string, o *origens) error {
	f, err := os.Open(lista)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	leitor := bufio.NewScanner(f)
	leitor.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for leitor.Scan() {
		var d struct{ Arquivo, Nome, Origem, Evidencia string }
		if err := json.Unmarshal(leitor.Bytes(), &d); err != nil {
			return err
		}
		relativo := filepath.FromSlash(d.Arquivo)
		// Quem escreve a lista e um modulo: ele nao escolhe arquivo fora da propria saida.
		if !filepath.IsLocal(relativo) {
			return fmt.Errorf("caminho fora da saida: %s", d.Arquivo)
		}
		pai, ok := o.evidencias[normalizarCaminho(d.Evidencia)]
		if !ok {
			return fmt.Errorf("evidencia de origem desconhecida: %s", d.Evidencia)
		}
		if err := guardarDerivado(c, filepath.Join(dirSaida, relativo), d.Nome, pai.Nome+"!"+d.Origem, pai.ID); err != nil {
			// Um arquivo bloqueado pelo antivirus nao pode derrubar os demais. Ele fica
			// registrado, porque um arquivo a menos muda o que o exame consegue afirmar.
			if _, falha := c.Custodia.Registrar("derivado.nao_preservado", map[string]any{
				"origem": d.Origem, "evidencia": pai.ID, "erro": caso.ExplicarAntivirus(err).Error(),
			}); falha != nil {
				return falha
			}
			continue
		}
	}
	return leitor.Err()
}

func guardarDerivado(c *caso.Caso, caminho, nome, origem string, pai int64) error {
	f, err := os.Open(caminho)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = c.AdicionarDerivado(f, nome, origem, pai)
	return err
}

// origens traduz o caminho de trabalho que a ferramenta viu para a evidencia real:
// a pasta temporaria nao diz nada a quem le o achado ou o laudo.
type origens struct {
	porCaminho map[string]string
	evidencias map[string]caso.Evidencia
	unica      string
}

func (o *origens) traduzir(caminho string) string {
	if evidencia, ok := o.porCaminho[normalizarCaminho(caminho)]; ok {
		return evidencia
	}
	if caminho == "" {
		return o.unica
	}
	return caminho
}

func normalizarCaminho(caminho string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(caminho), `\`, "/"))
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

func importar(c *caso.Caso, execucao int64, md *modulo.Manifesto, dirSaida string, o *origens) (int64, error) {
	arquivos, err := filepath.Glob(filepath.Join(dirSaida, filepath.FromSlash(md.Saida.Arquivos)))
	if err != nil {
		return 0, err
	}
	if len(arquivos) == 0 {
		return 0, nil
	}
	if len(md.Saida.Somente) > 0 {
		var escolhidos []string
		for _, arquivo := range arquivos {
			base := filepath.Base(arquivo)
			base = strings.TrimSuffix(base, filepath.Ext(base))
			for _, nome := range md.Saida.Somente {
				if strings.EqualFold(base, nome) {
					escolhidos = append(escolhidos, arquivo)
				}
			}
		}
		arquivos = escolhidos
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
			// Sem escapar & e <: o texto precisa continuar igual ao da evidencia, inclusive para
			// achar um arquivo pelo caminho.
			var buffer bytes.Buffer
			codificador := json.NewEncoder(&buffer)
			codificador.SetEscapeHTML(false)
			if err := codificador.Encode(r.Dados); err != nil {
				return err
			}
			dados := bytes.TrimSpace(buffer.Bytes())
			var quando any
			if r.Quando != "" {
				quando = r.Quando
			}
			res, err := inserir.Exec(execucao, r.Tipo, quando, r.QuandoBruto, r.Fonte, r.Descricao, r.Severidade, o.traduzir(r.OrigemArquivo), r.OrigemLocal, string(dados))
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

func hashPasta(pasta string) (string, error) {
	itens, err := os.ReadDir(pasta)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, item := range itens {
		if item.IsDir() {
			continue
		}
		sha, err := hashArquivo(filepath.Join(pasta, item.Name()))
		if err != nil {
			return "", err
		}
		fmt.Fprintln(h, item.Name(), sha)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
