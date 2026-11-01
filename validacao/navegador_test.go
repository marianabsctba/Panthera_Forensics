//go:build validacao

package validacao

import (
	"path/filepath"
	"testing"
)

// Amostras do proprio projeto Hindsight, nao do NIST. O total vem do conteudo dos
// arquivos: no Firefox, 3 visitas, 1 download, 1 pasta e 1 favorito.
func TestHindsightNaoPerdeItens(t *testing.T) {
	m, dados := ambiente(t)
	casos := map[string]struct {
		pasta     string
		total     int
		porFonte  map[string]int
		procurado string
	}{
		"Chrome":  {"chrome", 63, map[string]int{"url": 61, "download": 2}, "computer forensics"},
		"Firefox": {"firefox", 6, map[string]int{"url": 3, "download": 1, "bookmark": 1, "bookmark folder": 1}, "big_file.zip"},
	}
	for nome, esperado := range casos {
		t.Run(nome, func(t *testing.T) {
			c := processar(t, m, filepath.Join(dados, "hindsight", esperado.pasta))
			resumo, err := c.Resumir()
			if err != nil {
				t.Fatal(err)
			}
			if int(resumo.Registros) != esperado.total {
				t.Errorf("esperado %d itens, obtido %d", esperado.total, resumo.Registros)
			}
			for tipo, n := range esperado.porFonte {
				var obtido int
				if err := c.DB.QueryRow(`SELECT COUNT(*) FROM registros WHERE fonte=?`, "Navegador: "+tipo).Scan(&obtido); err != nil {
					t.Fatal(err)
				}
				if obtido != n {
					t.Errorf("%s: esperado %d, obtido %d", tipo, n, obtido)
				}
			}
			var semData int
			if err := c.DB.QueryRow(`SELECT COUNT(*) FROM registros WHERE quando IS NULL`).Scan(&semData); err != nil {
				t.Fatal(err)
			}
			if semData != 0 {
				t.Errorf("%d itens sem data", semData)
			}
		})
	}
}
