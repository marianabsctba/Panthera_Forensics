package relatorio

import (
	"strings"
	"testing"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
)

func TestConteudoHostilSaiEscapado(t *testing.T) {
	c, err := caso.Criar(t.TempDir(), "Caso <script>alert(1)</script>", "", "perita")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Fechar()
	if _, err := c.Adicionar(strings.NewReader("x"), "<img src=x onerror=alert(2)>.bin", "teste"); err != nil {
		t.Fatal(err)
	}
	var saida strings.Builder
	if err := Gerar(c, &saida); err != nil {
		t.Fatal(err)
	}
	html := saida.String()
	for _, proibido := range []string{"<script>alert", "<img src=x"} {
		if strings.Contains(html, proibido) {
			t.Fatalf("conteudo sem escape: %s", proibido)
		}
	}
	if !strings.Contains(html, "data:image/png;base64,") {
		t.Fatal("simbolo ausente")
	}
	if !strings.Contains(html, "Encadeamento íntegro") {
		t.Fatal("estado da custodia ausente")
	}
}
