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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/internal/instalador"
	"github.com/marianabsctba/Panthera_Forensics/internal/marca"
	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
	"github.com/marianabsctba/Panthera_Forensics/internal/motor"
	"github.com/marianabsctba/Panthera_Forensics/internal/relatorio"
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
	mux.HandleFunc("GET /api/casos/{id}/entidades", s.comCaso(s.entidades))
	mux.HandleFunc("GET /api/casos/{id}/evidencias", s.comCaso(s.evidencias))
	mux.HandleFunc("POST /api/casos/{id}/evidencias", s.comCaso(s.enviarEvidencia))
	mux.HandleFunc("POST /api/casos/{id}/processar", s.comCaso(s.processar))
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
	q := r.URL.Query()
	entidade, _ := strconv.ParseInt(q.Get("entidade"), 10, 64)
	limite, _ := strconv.Atoi(q.Get("limite"))
	deslocar, _ := strconv.Atoi(q.Get("deslocar"))
	linhas, err := c.Consultar(caso.Filtro{
		Texto: q.Get("q"), Tipo: q.Get("tipo"), Severidade: q.Get("severidade"),
		EntidadeID: entidade, Limite: limite, Deslocar: deslocar, Ordem: q.Get("ordem"),
	})
	if err != nil {
		falhar(w, http.StatusInternalServerError, err.Error())
		return
	}
	responder(w, linhas)
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
	responder(w, l)
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

func (s *Servidor) processar(w http.ResponseWriter, _ *http.Request, c *caso.Caso) {
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
	go s.rodar(c, e)
	responder(w, map[string]bool{"iniciado": true})
}

func (s *Servidor) rodar(c *caso.Caso, e *Estado) {
	for {
		res, err := s.Motor.Processar(context.Background(), c, func(etapa string, feitas, total int) {
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
		_, roda := m.ComandoAtual()
		_, temPacote := m.PacoteAtual()
		inst := instalador.Instalado(m, s.Motor.DirFerramentas) || (!temPacote && m.Dir != "")
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
func InstalarTodos(ctx context.Context, modulos []*modulo.Manifesto, dir string) error {
	var erros []error
	for _, m := range modulos {
		if err := instalador.Instalar(ctx, m, dir); err != nil {
			erros = append(erros, fmt.Errorf("%s: %w", m.Titulo, err))
		}
	}
	return errors.Join(erros...)
}
