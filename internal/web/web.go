// Package web serve a interface local. Ela escuta so em 127.0.0.1, recusa outro
// Host (DNS rebinding) e exige um token por sessao em tudo o que altera estado.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/internal/instalador"
	"github.com/marianabsctba/Panthera_Forensics/internal/marca"
	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
	"github.com/marianabsctba/Panthera_Forensics/internal/motor"
	"github.com/marianabsctba/Panthera_Forensics/internal/relatorio"
	"github.com/marianabsctba/Panthera_Forensics/modulos"
)

//go:embed estatico
var estatico embed.FS

// Estado e o que a tela mostra sobre o processamento de um caso.
type Estado struct {
	Rodando   bool             `json:"rodando"`
	Etapa     string           `json:"etapa"`
	Feitas    int              `json:"feitas"`
	Total     int              `json:"total"`
	Resultado *motor.Resultado `json:"resultado,omitempty"`
	Erro      string           `json:"erro,omitempty"`
	pendente  bool
}

// Servidor guarda os casos abertos e o estado de cada processamento.
type Servidor struct {
	DirCasos string
	Motor    *motor.Motor
	token    string
	host     string

	mu         sync.Mutex
	abertos    map[string]*caso.Caso
	estados    map[string]*Estado
	instalando bool
	erroInstal string
}

// Novo prepara o servidor com um token novo.
func Novo(dirCasos string, m *motor.Motor) (*Servidor, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Servidor{
		DirCasos: dirCasos, Motor: m, token: hex.EncodeToString(b),
		abertos: map[string]*caso.Caso{}, estados: map[string]*Estado{},
	}, nil
}

// Escutar abre a porta preferida ou, se estiver ocupada, qualquer porta livre.
func Escutar(porta int) (net.Listener, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", porta))
	if err == nil {
		return l, nil
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

// Handler monta as rotas para o endereco em que o servidor esta escutando.
func (s *Servidor) Handler(endereco string) http.Handler {
	s.host = endereco
	mux := http.NewServeMux()
	arquivos, _ := fs.Sub(estatico, "estatico")
	mux.Handle("GET /estatico/", http.StripPrefix("/estatico/", http.FileServerFS(arquivos)))
	mux.HandleFunc("GET /{$}", s.pagina)
	mux.HandleFunc("GET /simbolo.png", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(marca.Simbolo)
	})

	mux.HandleFunc("GET /api/casos", s.listarCasos)
	mux.HandleFunc("POST /api/casos", s.criarCaso)
	mux.HandleFunc("GET /api/modulos", s.listarModulos)
	mux.HandleFunc("POST /api/modulos/instalar", s.instalarModulos)
	mux.HandleFunc("GET /api/casos/{id}/resumo", s.comCaso(s.resumo))
	mux.HandleFunc("GET /api/casos/{id}/registros", s.comCaso(s.registros))
	mux.HandleFunc("GET /api/casos/{id}/registros/{rid}", s.comCaso(s.detalhe))
	mux.HandleFunc("POST /api/casos/{id}/registros/{rid}/marca", s.comCaso(s.marcar))
	mux.HandleFunc("GET /api/casos/{id}/atividade", s.comCaso(s.atividade))
	mux.HandleFunc("GET /api/casos/{id}/fontes", s.comCaso(s.fontes))
	mux.HandleFunc("GET /api/casos/{id}/visao", s.comCaso(s.visao))
	mux.HandleFunc("GET /api/casos/{id}/conexoes", s.comCaso(s.conexoes))
	mux.HandleFunc("GET /api/casos/{id}/entidades", s.comCaso(s.entidades))
	mux.HandleFunc("GET /api/casos/{id}/evidencias", s.comCaso(s.evidencias))
	mux.HandleFunc("POST /api/casos/{id}/evidencias", s.comCaso(s.enviarEvidencia))
	mux.HandleFunc("POST /api/casos/{id}/processar", s.comCaso(s.processar))
	mux.HandleFunc("GET /api/casos/{id}/aprofundar", s.comCaso(s.aprofundar))
	mux.HandleFunc("POST /api/casos/{id}/abrir-analise", s.comCaso(s.abrirAnalise))
	mux.HandleFunc("GET /api/casos/{id}/estado", s.comCaso(s.estado))
	mux.HandleFunc("POST /api/casos/{id}/verificar", s.comCaso(s.verificar))
	mux.HandleFunc("GET /casos/{id}/relatorio", s.comCaso(s.relatorio))
	return s.protegido(mux)
}

func (s *Servidor) protegido(prox http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.host {
			http.Error(w, "host recusado", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(s.token)) != 1 {
				http.Error(w, "token invalido", http.StatusForbidden)
				return
			}
		}
		// O conteudo exibido vem da evidencia: nada de script inline ou recurso externo.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		prox.ServeHTTP(w, r)
	})
}

func (s *Servidor) pagina(w http.ResponseWriter, _ *http.Request) {
	dados, err := estatico.ReadFile("estatico/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(strings.Replace(string(dados), "{{TOKEN}}", s.token, 1)))
}

func responder(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func falhar(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"erro": msg})
}

var idValido = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$`)

func (s *Servidor) comCaso(h func(http.ResponseWriter, *http.Request, *caso.Caso)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !idValido.MatchString(id) {
			falhar(w, http.StatusNotFound, "Caso não encontrado.")
			return
		}
		s.mu.Lock()
		c, ok := s.abertos[id]
		s.mu.Unlock()
		if !ok {
			aberto, err := caso.Abrir(filepath.Join(s.DirCasos, id))
			if errors.Is(err, os.ErrNotExist) {
				falhar(w, http.StatusNotFound, "Caso não encontrado.")
				return
			}
			if err != nil {
				falhar(w, http.StatusConflict, "Não foi possível abrir o caso: "+err.Error())
				return
			}
			s.mu.Lock()
			if atual, ok := s.abertos[id]; ok {
				aberto.Fechar()
				c = atual
			} else {
				s.abertos[id] = aberto
				c = aberto
			}
			s.mu.Unlock()
		}
		h(w, r, c)
	}
}

func (s *Servidor) listarCasos(w http.ResponseWriter, _ *http.Request) {
	casos, err := caso.Listar(s.DirCasos)
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	if casos == nil {
		casos = []caso.Info{}
	}
	responder(w, casos)
}

func (s *Servidor) criarCaso(w http.ResponseWriter, r *http.Request) {
	var p struct{ Nome, Numero, Perito string }
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		falhar(w, http.StatusBadRequest, "Dados inválidos.")
		return
	}
	c, err := caso.Criar(s.DirCasos, p.Nome, p.Numero, p.Perito)
	if err != nil {
		falhar(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	s.abertos[c.Info.ID] = c
	s.mu.Unlock()
	responder(w, c.Info)
}

func (s *Servidor) resumo(w http.ResponseWriter, _ *http.Request, c *caso.Caso) {
	res, err := c.Resumir()
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, map[string]any{"caso": c.Info, "resumo": res})
}

func (s *Servidor) registros(w http.ResponseWriter, r *http.Request, c *caso.Caso) {
	linhas, err := c.Consultar(filtroDe(r))
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, linhas)
}

func filtroDe(r *http.Request) caso.Filtro {
	q := r.URL.Query()
	entidade, _ := strconv.ParseInt(q.Get("entidade"), 10, 64)
	limite, _ := strconv.Atoi(q.Get("limite"))
	deslocar, _ := strconv.Atoi(q.Get("deslocar"))
	return caso.Filtro{
		Texto: q.Get("q"), Tipo: q.Get("tipo"), Severidade: q.Get("severidade"),
		EntidadeID: entidade, Limite: limite, Deslocar: deslocar, Ordem: q.Get("ordem"),
		De: q.Get("de"), Ate: q.Get("ate"), Fonte: q.Get("fonte"), Marcados: q.Get("marcados") == "1",
	}
}

func (s *Servidor) atividade(w http.ResponseWriter, r *http.Request, c *caso.Caso) {
	a, err := c.Atividade(filtroDe(r))
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, a)
}

func (s *Servidor) fontes(w http.ResponseWriter, r *http.Request, c *caso.Caso) {
	lista, err := c.Fontes(filtroDe(r))
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, lista)
}

func (s *Servidor) visao(w http.ResponseWriter, _ *http.Request, c *caso.Caso) {
	v, err := c.Visao()
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, v)
}

func (s *Servidor) conexoes(w http.ResponseWriter, _ *http.Request, c *caso.Caso) {
	m, err := c.Conexoes(30)
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, m)
}

func (s *Servidor) marcar(w http.ResponseWriter, r *http.Request, c *caso.Caso) {
	id, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err != nil {
		falhar(w, http.StatusNotFound, "Registro não encontrado.")
		return
	}
	var p struct {
		Marcado bool
		Nota    string
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		falhar(w, http.StatusBadRequest, "Dados inválidos.")
		return
	}
	if p.Marcado {
		err = c.Marcar(id, p.Nota)
	} else {
		err = c.Desmarcar(id)
	}
	if err != nil {
		falhar(w, http.StatusNotFound, "Não foi possível guardar a marcação.")
		return
	}
	responder(w, map[string]bool{"ok": true})
}

func (s *Servidor) detalhe(w http.ResponseWriter, r *http.Request, c *caso.Caso) {
	id, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err != nil {
		falhar(w, http.StatusNotFound, "Registro não encontrado.")
		return
	}
	l, err := c.Detalhe(id)
	if err != nil {
		falhar(w, http.StatusNotFound, "Registro não encontrado.")
		return
	}
	marcado, nota, err := c.NotaDe(id)
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, struct {
		caso.Linha
		Marcado bool   `json:"marcado"`
		Nota    string `json:"nota"`
	}{l, marcado, nota})
}

func (s *Servidor) entidades(w http.ResponseWriter, r *http.Request, c *caso.Caso) {
	lista, err := c.Entidades(r.URL.Query().Get("tipo"), 200)
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, lista)
}

func (s *Servidor) evidencias(w http.ResponseWriter, _ *http.Request, c *caso.Caso) {
	lista, err := c.Evidencias()
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	execucoes, err := c.Execucoes()
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, map[string]any{"evidencias": lista, "execucoes": execucoes})
}

// enviarEvidencia recebe o corpo como fluxo, para aguentar imagens grandes sem
// carregar nada em memoria.
func (s *Servidor) enviarEvidencia(w http.ResponseWriter, r *http.Request, c *caso.Caso) {
	q := r.URL.Query()
	nome := filepath.Base(filepath.FromSlash(strings.ReplaceAll(q.Get("nome"), `\`, "/")))
	if nome == "." || nome == string(filepath.Separator) {
		falhar(w, http.StatusBadRequest, "Arquivo sem nome.")
		return
	}
	origem := q.Get("origem")
	if origem == "" {
		origem = nome
	}
	novas, err := c.Adicionar(r.Body, nome, "enviado pela interface: "+origem)
	if err != nil {
		falhar(w, http.StatusInternalServerError, "Não consegui guardar "+nome+": "+err.Error())
		return
	}
	responder(w, novas)
}

func (s *Servidor) processar(w http.ResponseWriter, r *http.Request, c *caso.Caso) {
	refazer := r.URL.Query().Get("refazer") == "1"
	profundo := r.URL.Query().Get("profundo") == "1"
	id := c.Info.ID
	s.mu.Lock()
	e, ok := s.estados[id]
	if !ok {
		e = &Estado{}
		s.estados[id] = e
	}
	if e.Rodando {
		// Chegou evidencia nova durante o processamento: roda de novo ao terminar.
		e.pendente = true
		s.mu.Unlock()
		responder(w, map[string]bool{"iniciado": false})
		return
	}
	e.Rodando, e.Erro, e.Resultado = true, "", nil
	s.mu.Unlock()
	go s.rodar(c, e, refazer, profundo)
	responder(w, map[string]bool{"iniciado": true})
}

func (s *Servidor) rodar(c *caso.Caso, e *Estado, refazer, profundo bool) {
	m := s.Motor
	if refazer || profundo {
		m = s.Motor.Variante(refazer, profundo)
	}
	if profundo {
		s.mu.Lock()
		e.Etapa, e.Feitas, e.Total = "Preparando o exame profundo", 0, 1
		s.mu.Unlock()
		if err := InstalarOpcionais(context.Background(), s.Motor.Modulos, s.Motor.DirFerramentas); err != nil {
			s.mu.Lock()
			e.Erro, e.Rodando = "Não foi possível preparar o exame profundo: "+err.Error(), false
			s.mu.Unlock()
			return
		}
	}
	for {
		res, err := m.Processar(context.Background(), c, func(etapa string, feitas, total int) {
			s.mu.Lock()
			e.Etapa, e.Feitas, e.Total = etapa, feitas, total
			s.mu.Unlock()
		})
		s.mu.Lock()
		e.Resultado = &res
		if err != nil {
			e.Erro = err.Error()
		}
		if e.pendente {
			e.pendente = false
			s.mu.Unlock()
			continue
		}
		e.Rodando = false
		s.mu.Unlock()
		return
	}
}

func (s *Servidor) estado(w http.ResponseWriter, _ *http.Request, c *caso.Caso) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.estados[c.Info.ID]
	if !ok {
		responder(w, Estado{})
		return
	}
	responder(w, *e)
}

func (s *Servidor) verificar(w http.ResponseWriter, _ *http.Request, c *caso.Caso) {
	conf, err := c.Verificar()
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, conf)
}

func (s *Servidor) relatorio(w http.ResponseWriter, _ *http.Request, c *caso.Caso) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
	if err := relatorio.Gerar(c, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Servidor) listarModulos(w http.ResponseWriter, _ *http.Request) {
	type item struct {
		Nome      string `json:"nome"`
		Titulo    string `json:"titulo"`
		Versao    string `json:"versao"`
		Instalado bool   `json:"instalado"`
		Roda      bool   `json:"roda"`
	}
	itens := []item{}
	pendentes := 0
	for _, m := range s.Motor.Modulos {
		// Opcionais so sao preparados quando o exame profundo e pedido.
		if m.Opcional {
			continue
		}
		_, roda := m.ComandoAtual()
		_, temPacote := m.PacoteAtual()
		inst := instalador.Instalado(m, s.Motor.DirFerramentas) || (!temPacote && m.Dir != "")
		if m.RequerWSL {
			inst = instalador.WSLPreparado(dirWSL(s.Motor.DirFerramentas))
		}
		if roda && !inst {
			pendentes++
		}
		itens = append(itens, item{m.Nome, m.Titulo, m.Versao, inst, roda})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	responder(w, map[string]any{"modulos": itens, "pendentes": pendentes, "instalando": s.instalando, "erro": s.erroInstal})
}

func (s *Servidor) instalarModulos(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	if s.instalando {
		s.mu.Unlock()
		responder(w, map[string]bool{"iniciado": false})
		return
	}
	s.instalando, s.erroInstal = true, ""
	s.mu.Unlock()
	go func() {
		err := InstalarTodos(context.Background(), s.Motor.Modulos, s.Motor.DirFerramentas)
		s.mu.Lock()
		s.instalando = false
		if err != nil {
			s.erroInstal = err.Error()
		}
		s.mu.Unlock()
	}()
	responder(w, map[string]bool{"iniciado": true})
}

// InstalarTodos instala o que puder e informa todas as falhas de uma vez.
func InstalarTodos(ctx context.Context, lista []*modulo.Manifesto, dir string) error {
	var erros []error
	precisaWSL := false
	for _, m := range lista {
		if m.Opcional {
			continue
		}
		precisaWSL = precisaWSL || m.RequerWSL
		if err := instalador.Instalar(ctx, m, dir); err != nil {
			erros = append(erros, fmt.Errorf("%s: %w", m.Titulo, err))
		}
	}
	if precisaWSL {
		if err := instalador.PrepararWSL(ctx, dirWSL(dir), modulos.PrepararWSL); err != nil {
			erros = append(erros, fmt.Errorf("Ambiente Linux: %w", err))
		}
	}
	return errors.Join(erros...)
}

// InstalarOpcionais prepara o que so o exame profundo usa.
func InstalarOpcionais(ctx context.Context, lista []*modulo.Manifesto, dir string) error {
	var erros []error
	precisaWSL := false
	for _, m := range lista {
		if !m.Opcional {
			continue
		}
		precisaWSL = precisaWSL || m.RequerWSL
		if err := instalador.Instalar(ctx, m, dir); err != nil {
			erros = append(erros, fmt.Errorf("%s: %w", m.Titulo, err))
		}
	}
	if precisaWSL {
		if err := instalador.PrepararWSL(ctx, dirWSL(dir), modulos.PrepararWSL); err != nil {
			erros = append(erros, fmt.Errorf("Ambiente Linux: %w", err))
		}
	}
	return errors.Join(erros...)
}

// aprofundar diz se o exame profundo se aplica a este caso e o que ja pode ser aberto.
func (s *Servidor) aprofundar(w http.ResponseWriter, _ *http.Request, c *caso.Caso) {
	evidencias, err := c.Evidencias()
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	tipos := map[string]bool{}
	for _, e := range evidencias {
		tipos[e.Tipo] = true
	}
	aplicavel := false
	for _, m := range s.Motor.Modulos {
		if m.Opcional {
			aplicavel = aplicavel || slices.ContainsFunc(m.Consome, func(t string) bool { return tipos[t] })
		}
	}
	_, pronto := s.programaAnalise(c)
	responder(w, map[string]bool{"aplicavel": aplicavel, "pronto": pronto})
}

// programaAnalise procura o programa deixado por um modulo na pasta da execucao. O
// caminho vem do manifesto e do numero da execucao, e nunca do pedido.
func (s *Servidor) programaAnalise(c *caso.Caso) (string, bool) {
	execucoes, err := c.Execucoes()
	if err != nil {
		return "", false
	}
	for i := len(execucoes) - 1; i >= 0; i-- {
		x := execucoes[i]
		if x.Estado != "concluida" {
			continue
		}
		for _, m := range s.Motor.Modulos {
			if m.Nome == x.Modulo && m.Abrir != "" {
				caminho := filepath.Join(c.Dir, "execucoes", strconv.FormatInt(x.ID, 10), "saida", filepath.FromSlash(m.Abrir))
				if _, err := os.Stat(caminho); err == nil {
					return caminho, true
				}
			}
		}
	}
	return "", false
}

func (s *Servidor) abrirAnalise(w http.ResponseWriter, _ *http.Request, c *caso.Caso) {
	caminho, ok := s.programaAnalise(c)
	if !ok {
		falhar(w, http.StatusNotFound, "O exame profundo ainda não foi feito neste caso.")
		return
	}
	cmd := exec.Command(caminho)
	cmd.Dir = filepath.Dir(caminho)
	if err := cmd.Start(); err != nil {
		falhar(w, http.StatusInternalServerError, "Não foi possível abrir: "+err.Error())
		return
	}
	go cmd.Wait()
	if _, err := c.Custodia.Registrar("analise.aberta", map[string]any{"programa": filepath.Base(caminho)}); err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, map[string]bool{"ok": true})
}

func dirWSL(dirFerramentas string) string {
	return filepath.Join(filepath.Dir(dirFerramentas), "wsl")
}
