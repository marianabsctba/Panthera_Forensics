//go:build validacao

// Package validacao compara o resultado do Panthera Forensics com os dados de
// referencia do NIST (CFReDS). Os testes rodam as ferramentas reais e exigem:
//
//	PANTHERA_HOME   pasta com as ferramentas instaladas
//	PANTHERA_DADOS  pasta com os dados, conforme validacao/README.md
//
// Rodam com: go test -tags validacao -v -count=1 ./validacao
package validacao

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
	"github.com/marianabsctba/Panthera_Forensics/internal/motor"
	"github.com/marianabsctba/Panthera_Forensics/modulos"
)

func ambiente(t *testing.T) (*motor.Motor, string) {
	t.Helper()
	home, dados := os.Getenv("PANTHERA_HOME"), os.Getenv("PANTHERA_DADOS")
	if home == "" || dados == "" {
		t.Fatal("defina PANTHERA_HOME e PANTHERA_DADOS")
	}
	embutidos, err := modulo.CarregarFS(modulos.Embutidos)
	if err != nil {
		t.Fatal(err)
	}
	return &motor.Motor{Modulos: embutidos, DirFerramentas: filepath.Join(home, "ferramentas")}, dados
}

// processar leva a evidencia pelo fluxo real e exige que nenhuma leitura falhe.
func processar(t *testing.T, m *motor.Motor, caminho string) *caso.Caso {
	t.Helper()
	c, err := caso.Criar(t.TempDir(), "Validacao "+t.Name(), "", "validacao")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Fechar() })
	if _, err := c.AdicionarCaminho(caminho); err != nil {
		t.Fatal(err)
	}
	res, err := m.Processar(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Falhas) != 0 || len(res.Ausentes) != 0 || res.Executadas == 0 {
		t.Fatalf("processamento incompleto: %+v", res)
	}
	return c
}

// linhasOriginais devolve cada linha bruta da ferramenta, uma vez por entrada da MFT.
func linhasOriginais(t *testing.T, db *sql.DB) map[string]map[string]string {
	t.Helper()
	linhas, err := db.Query(`SELECT dados FROM registros`)
	if err != nil {
		t.Fatal(err)
	}
	defer linhas.Close()
	saida := map[string]map[string]string{}
	for linhas.Next() {
		var bruto string
		if err := linhas.Scan(&bruto); err != nil {
			t.Fatal(err)
		}
		var d map[string]string
		if err := json.Unmarshal([]byte(bruto), &d); err != nil {
			t.Fatal(err)
		}
		saida[d["FileName"]] = d
	}
	return saida
}

// DFR-01: um arquivo apagado (Bunda.txt) e dois ativos. Gabarito na secao ntfs-01 do
// documento de layout do NIST; as datas estao em -0500 la e em UTC aqui.
func TestDFR01ArquivoApagado(t *testing.T) {
	m, dados := ambiente(t)
	c := processar(t, m, filepath.Join(dados, "nist-dfr", "mft-01", "p61", "$MFT"))
	arquivos := linhasOriginais(t, c.DB)

	bunda, ok := arquivos["Bunda.txt"]
	if !ok {
		t.Fatal("Bunda.txt nao encontrado")
	}
	esperado := map[string]string{
		"InUse":            "False",
		"FileSize":         "4296",
		"LastModified0x10": "2000-02-29 18:14:00",
		"LastAccess0x10":   "1999-01-02 08:04:00",
		// Change do gabarito, medida antes da exclusao. A exclusao foi as 15:25 UTC, e a
		// MFT nao a registra: quem le a timeline nao pode tomar esta data por ela.
		"LastRecordChange0x10": "2012-02-03 15:12:59.67488",
	}
	for campo, valor := range esperado {
		if !strings.HasPrefix(bunda[campo], valor) {
			t.Errorf("Bunda.txt %s: esperado %s, obtido %s", campo, valor, bunda[campo])
		}
	}
	for _, nome := range []string{"Arcturus.txt", "Castor.txt"} {
		if arquivos[nome]["InUse"] != "True" {
			t.Errorf("%s deveria estar ativo: %+v", nome, arquivos[nome])
		}
	}
	apagados, err := c.Consultar(caso.Filtro{Texto: "Bunda.txt"})
	if err != nil {
		t.Fatal(err)
	}
	achou := false
	for _, l := range apagados {
		achou = achou || strings.HasPrefix(l.Descricao, "Arquivo apagado em momento desconhecido")
	}
	if !achou {
		t.Error("a exclusao de Bunda.txt nao aparece na timeline como momento desconhecido")
	}
}

var nomeDFR16 = regexp.MustCompile(`\b4-\d{2}-\d{5}\.txt\b`)

// DFR-16: a lista de arquivos ativos publicada pelo NIST precisa aparecer inteira.
func TestDFR16ListaDeArquivos(t *testing.T) {
	m, dados := ambiente(t)
	bruto, err := os.ReadFile(filepath.Join(dados, "nist-dfr", "setup.txt"))
	if err != nil {
		t.Fatal(err)
	}
	texto := string(bruto)
	inicio := strings.LastIndex(texto, "Test Image ntfs-16")
	fim := strings.LastIndex(texto, "Test Image ntfs-17")
	if inicio < 0 || fim <= inicio {
		t.Fatal("secao ntfs-16 nao encontrada no documento")
	}
	gabarito := map[string]bool{}
	for _, n := range nomeDFR16.FindAllString(texto[inicio:fim], -1) {
		gabarito[n] = true
	}
	if len(gabarito) == 0 {
		t.Fatal("gabarito vazio")
	}

	c := processar(t, m, filepath.Join(dados, "nist-dfr", "mft-16", "p128", "$MFT"))
	arquivos := linhasOriginais(t, c.DB)
	var faltando, inativos []string
	for nome := range gabarito {
		d, ok := arquivos[nome]
		switch {
		case !ok:
			faltando = append(faltando, nome)
		case d["InUse"] != "True":
			inativos = append(inativos, nome)
		}
	}
	sort.Strings(faltando)
	sort.Strings(inativos)
	t.Logf("gabarito: %d arquivos; encontrados na saida: %d registros distintos", len(gabarito), len(arquivos))
	if len(faltando) > 0 {
		t.Errorf("%d arquivos do gabarito faltando: %v", len(faltando), faltando)
	}
	if len(inativos) > 0 {
		t.Errorf("%d arquivos do gabarito marcados como apagados: %v", len(inativos), inativos)
	}
}
