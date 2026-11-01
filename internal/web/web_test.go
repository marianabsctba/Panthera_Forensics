package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marianabsctba/Panthera_Forensics/internal/motor"
)

func montar(t *testing.T) (*Servidor, http.Handler) {
	t.Helper()
	s, err := Novo(t.TempDir(), &motor.Motor{DirFerramentas: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return s, s.Handler("127.0.0.1:7878")
}

func pedir(h http.Handler, metodo, rota, host, token, corpo string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(metodo, rota, strings.NewReader(corpo))
	r.Host = host
	if token != "" {
		r.Header.Set("X-Token", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRecusaHostExterno(t *testing.T) {
	_, h := montar(t)
	if w := pedir(h, "GET", "/api/casos", "atacante.exemplo", "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("host externo aceito: %d", w.Code)
	}
}

func TestEscritaExigeToken(t *testing.T) {
	s, h := montar(t)
	host := "127.0.0.1:7878"
	if w := pedir(h, "POST", "/api/casos", host, "", `{"Nome":"x"}`); w.Code != http.StatusForbidden {
		t.Fatalf("sem token aceito: %d", w.Code)
	}
	if w := pedir(h, "POST", "/api/casos", host, s.token, `{"Nome":"x"}`); w.Code != http.StatusOK {
		t.Fatalf("com token recusado: %d %s", w.Code, w.Body)
	}
	for _, a := range s.abertos {
		a.Fechar()
	}
}

func TestIdDeCasoNaoEscapaDaPasta(t *testing.T) {
	_, h := montar(t)
	w := pedir(h, "GET", "/api/casos/..%2F..%2Fwindows/resumo", "127.0.0.1:7878", "", "")
	if w.Code == http.StatusOK {
		t.Fatal("id hostil aceito")
	}
}

func TestPaginaTemPoliticaDeConteudo(t *testing.T) {
	s, h := montar(t)
	w := pedir(h, "GET", "/", "127.0.0.1:7878", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("pagina: %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatal("sem politica de conteudo")
	}
	if !strings.Contains(w.Body.String(), s.token) {
		t.Fatal("token ausente da pagina")
	}
}
