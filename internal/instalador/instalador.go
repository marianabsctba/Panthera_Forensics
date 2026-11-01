// Package instalador baixa as ferramentas dos modulos. Nada e aproveitado sem que o
// SHA-256 baixado seja igual ao fixado no manifesto.
package instalador

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
)

// Instalado diz se a ferramenta do modulo ja esta na pasta.
func Instalado(m *modulo.Manifesto, dirFerramentas string) bool {
	_, err := os.Stat(filepath.Join(dirFerramentas, m.Ferramenta, m.Versao, ".instalado"))
	return err == nil
}

// Instalar baixa, confere e extrai a ferramenta do modulo. Sem pacote para este
// sistema, nao ha o que fazer e nao e erro.
func Instalar(ctx context.Context, m *modulo.Manifesto, dirFerramentas string) error {
	p, ok := m.PacoteAtual()
	if !ok || Instalado(m, dirFerramentas) {
		return nil
	}
	destino := filepath.Join(dirFerramentas, m.Ferramenta, m.Versao)
	if err := os.MkdirAll(filepath.Dir(destino), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destino), "baixando-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: resposta %s", p.URL, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		return err
	}
	if obtido := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(obtido, p.SHA256) {
		return fmt.Errorf("%s: hash %s difere do esperado %s", p.URL, obtido, p.SHA256)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.RemoveAll(destino); err != nil {
		return err
	}
	if p.Arquivo != "" {
		// A ferramenta e um executavel unico, sem pacote para abrir.
		if err := os.MkdirAll(destino, 0o755); err != nil {
			return err
		}
		if err := os.Rename(tmp.Name(), filepath.Join(destino, filepath.Base(p.Arquivo))); err != nil {
			return err
		}
	} else if err := extrair(tmp.Name(), destino); err != nil {
		os.RemoveAll(destino)
		return err
	}
	return os.WriteFile(filepath.Join(destino, ".instalado"), []byte(p.SHA256+"\n"), 0o644)
}

func extrair(pacote, destino string) error {
	z, err := zip.OpenReader(pacote)
	if err != nil {
		return err
	}
	defer z.Close()
	base, err := filepath.Abs(destino)
	if err != nil {
		return err
	}
	for _, f := range z.File {
		alvo := filepath.Join(base, filepath.FromSlash(f.Name))
		if alvo != base && !strings.HasPrefix(alvo, base+string(filepath.Separator)) {
			return fmt.Errorf("caminho fora do destino no pacote: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(alvo, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(alvo), 0o755); err != nil {
			return err
		}
		if err := extrairArquivo(f, alvo); err != nil {
			return err
		}
	}
	return nil
}

func extrairArquivo(f *zip.File, alvo string) error {
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	w, err := os.OpenFile(alvo, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}
