//go:build validacao

package validacao

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/modulos"
)

func contarPorModulo(t *testing.T, c *caso.Caso, modulo, filtro string, args ...any) int {
	t.Helper()
	var n int
	q := `SELECT COUNT(*) FROM registros r JOIN execucoes e ON e.id=r.execucao_id WHERE e.modulo=? AND ` + filtro
	if err := c.DB.QueryRow(q, append([]any{modulo}, args...)...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Alerta conhecido: o proprio projeto Suricata espera a regra 2100498 nesta captura.
func TestRedeComAlertaConhecido(t *testing.T) {
	m, dados := ambiente(t)
	c := processar(t, m, filepath.Join(dados, "pcap", "testmyids.pcap"))
	if n := contarPorModulo(t, c, "suricata", `r.tipo='alerta' AND r.origem_local LIKE '%regra 2100498%'`); n != 1 {
		t.Errorf("regra 2100498: esperado 1 alerta, obtido %d", n)
	}
	var quando string
	if err := c.DB.QueryRow(`SELECT quando FROM registros WHERE origem_local LIKE '%regra 2100498%'`).Scan(&quando); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(quando, "2016-07-13T22:42:07") {
		t.Errorf("fuso -0300 nao convertido: %s", quando)
	}
	if n := contarPorModulo(t, c, "zeek", `r.descricao LIKE '%82.165.177.154%' OR r.fonte='Rede: conexão'`); n == 0 {
		t.Error("zeek nao registrou a conexao")
	}
}

// Nome malicioso chega a ferramenta como texto, sem executar comando nenhum.
func TestNomeHostilNaoExecutaComando(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("ambiente Linux dedicado so existe no Windows")
	}
	m, dados := ambiente(t)
	original, err := os.ReadFile(filepath.Join(dados, "pcap", "hacking-packets.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	pasta := t.TempDir()
	nome := "a'$(touch PWNED)x;touch PWNED2 & b.pcap"
	// Conteudo cortado de proposito: testa tambem a leitura parcial.
	if err := os.WriteFile(filepath.Join(pasta, nome), append(original, 'x'), 0o644); err != nil {
		t.Fatal(err)
	}
	c := processar(t, m, filepath.Join(pasta, nome))
	execucoes, err := c.Execucoes()
	if err != nil {
		t.Fatal(err)
	}
	parciais := 0
	for _, x := range execucoes {
		if strings.HasPrefix(x.Erro, "leitura parcial") {
			parciais++
			if x.Registros == 0 {
				t.Errorf("%s: leitura parcial sem registros", x.Modulo)
			}
		}
	}
	if parciais == 0 {
		t.Error("captura cortada deveria ser marcada como parcial")
	}
	achados, err := filepath.Glob(filepath.Join(c.Dir, "execucoes", "*", "*", "PWNED*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(achados) != 0 {
		t.Fatalf("comando executado a partir do nome: %v", achados)
	}
}

func TestChainsawEmLogsReais(t *testing.T) {
	m, dados := ambiente(t)
	c := processar(t, m, filepath.Join(dados, "hayabusa-sample-evtx", "DeepBlueCLI", "eventlog-dac.evtx"))
	if n := contarPorModulo(t, c, "chainsaw", `r.tipo='alerta' AND r.severidade='critica' AND r.descricao='Security Audit Logs Cleared'`); n != 1 {
		t.Errorf("log limpo deveria gerar 1 alerta critico, obtido %d", n)
	}
}

func TestExecutavelLimpoNaoGeraAlerta(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("usa binario do Windows")
	}
	m, _ := ambiente(t)
	c := processar(t, m, `C:\Windows\System32\notepad.exe`)
	if n := contarPorModulo(t, c, "yara", `r.tipo='alerta'`); n != 0 {
		t.Errorf("alarme falso em notepad.exe: %d", n)
	}
	if n := contarPorModulo(t, c, "capa", `1=1`); n == 0 {
		t.Error("capa nao descreveu nenhuma capacidade")
	}
}

// As regras embutidas precisam ser gravadas para o ambiente de validacao.
func init() {
	if home := os.Getenv("PANTHERA_HOME"); home != "" {
		if err := modulos.GravarRegras(filepath.Join(home, "regras")); err != nil {
			panic(err)
		}
	}
}
