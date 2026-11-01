package custodia

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func criar(t *testing.T) string {
	t.Helper()
	caminho := filepath.Join(t.TempDir(), "custodia.jsonl")
	r, err := Abrir(caminho, "perita")
	if err != nil {
		t.Fatal(err)
	}
	for _, acao := range []string{"caso.criado", "evidencia.adicionada", "modulo.executado"} {
		if _, err := r.Registrar(acao, map[string]any{"valor": acao}); err != nil {
			t.Fatal(err)
		}
	}
	return caminho
}

func TestCadeiaIntegra(t *testing.T) {
	caminho := criar(t)
	entradas, err := Ler(caminho)
	if err != nil {
		t.Fatal(err)
	}
	if len(entradas) != 3 {
		t.Fatalf("esperava 3 entradas, veio %d", len(entradas))
	}
	if err := Verificar(entradas); err != nil {
		t.Fatal(err)
	}
}

func TestContinuaAposReabrir(t *testing.T) {
	caminho := criar(t)
	r, err := Abrir(caminho, "perita")
	if err != nil {
		t.Fatal(err)
	}
	e, err := r.Registrar("caso.reaberto", nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 4 {
		t.Fatalf("esperava seq 4, veio %d", e.Seq)
	}
	entradas, _ := Ler(caminho)
	if err := Verificar(entradas); err != nil {
		t.Fatal(err)
	}
}

func TestDetectaAdulteracao(t *testing.T) {
	casos := map[string]func([]string) []string{
		"conteudo alterado": func(l []string) []string {
			l[1] = strings.Replace(l[1], "evidencia.adicionada", "evidencia.removida", 1)
			return l
		},
		"linha removida": func(l []string) []string { return append(l[:1], l[2:]...) },
		"linhas trocadas": func(l []string) []string {
			l[0], l[1] = l[1], l[0]
			return l
		},
	}
	for nome, adulterar := range casos {
		t.Run(nome, func(t *testing.T) {
			caminho := criar(t)
			bruto, err := os.ReadFile(caminho)
			if err != nil {
				t.Fatal(err)
			}
			linhas := adulterar(strings.Split(strings.TrimSpace(string(bruto)), "\n"))
			if err := os.WriteFile(caminho, []byte(strings.Join(linhas, "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			entradas, err := Ler(caminho)
			if err != nil {
				t.Fatal(err)
			}
			if Verificar(entradas) == nil {
				t.Fatal("adulteracao nao detectada")
			}
			if _, err := Abrir(caminho, "perita"); err == nil {
				t.Fatal("registro adulterado nao deveria abrir")
			}
		})
	}
}
