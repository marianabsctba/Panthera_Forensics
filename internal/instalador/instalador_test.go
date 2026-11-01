package instalador

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
)

func pacote(t *testing.T, nome string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, err := z.Create(nome)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("conteudo"))
	z.Close()
	return b.Bytes()
}

func manifesto(url, sha string) *modulo.Manifesto {
	return &modulo.Manifesto{Ferramenta: "x", Versao: "1", Instalar: map[string]modulo.Pacote{
		runtime.GOOS + "-" + runtime.GOARCH: {URL: url, SHA256: sha},
	}}
}

func servir(t *testing.T, dados []byte) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(dados) }))
	t.Cleanup(s.Close)
	return s.URL
}

func TestInstalaComHashCerto(t *testing.T) {
	dados := pacote(t, "pasta/ferramenta.exe")
	soma := sha256.Sum256(dados)
	dir := t.TempDir()
	m := manifesto(servir(t, dados), hex.EncodeToString(soma[:]))
	if err := Instalar(context.Background(), m, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x", "1", "pasta", "ferramenta.exe")); err != nil {
		t.Fatal(err)
	}
	if !Instalado(m, dir) {
		t.Fatal("deveria constar como instalado")
	}
}

func TestRecusaHashErrado(t *testing.T) {
	dir := t.TempDir()
	m := manifesto(servir(t, pacote(t, "a.exe")), "00000000000000000000000000000000000000000000000000000000000000ff")
	if err := Instalar(context.Background(), m, dir); err == nil {
		t.Fatal("hash errado deveria ser recusado")
	}
	if Instalado(m, dir) {
		t.Fatal("nao deveria constar como instalado")
	}
}

func TestRecusaCaminhoForaDoDestino(t *testing.T) {
	dados := pacote(t, "../../fora.exe")
	soma := sha256.Sum256(dados)
	dir := t.TempDir()
	m := manifesto(servir(t, dados), hex.EncodeToString(soma[:]))
	if err := Instalar(context.Background(), m, dir); err == nil {
		t.Fatal("caminho hostil deveria ser recusado")
	}
	if _, err := os.Stat(filepath.Join(dir, "fora.exe")); err == nil {
		t.Fatal("arquivo escapou do destino")
	}
}
