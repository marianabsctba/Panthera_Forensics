package disco

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParticoesDoMmls(t *testing.T) {
	saida := `DOS Partition Table
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000000060   0000000061   Unallocated
002:  000:000   0000000061   0000586941   0000586881   NTFS / exFAT (0x07)
`
	p := InterpretarMmls(saida)
	if len(p) != 1 || p[0].Inicio != 61 || !strings.HasPrefix(p[0].Descricao, "NTFS") {
		t.Fatalf("particoes erradas: %+v", p)
	}
	if v := InterpretarMmls(""); len(v) != 1 || v[0].Inicio != 0 {
		t.Fatalf("sem tabela deveria virar um volume: %+v", v)
	}
}

// Linhas reais do DFR-01 do NIST.
func TestBodyDistingueApagadoDeResidual(t *testing.T) {
	apagado, ok := InterpretarBody("0|/Bunda.txt (deleted)|65-128-2|-/rrwxrwxrwx|48|0|4296|915264240|951848040|1328281979|1328281801")
	if !ok || !apagado.Apagado || apagado.Residual || apagado.Caminho != "/Bunda.txt" || apagado.Tamanho != 4296 {
		t.Fatalf("apagado mal lido: %+v", apagado)
	}
	residual, _ := InterpretarBody("0|/Castor.txt (deleted)|0|r/----------|0|0|0|0|0|0|0")
	if residual.Apagado || !residual.Residual {
		t.Fatalf("nome residual nao pode virar arquivo apagado: %+v", residual)
	}
	ativo, _ := InterpretarBody("0|/Castor.txt|66-128-2|r/rrwxrwxrwx|48|0|4096|915170460|915170460|1328281979|1328281801")
	if ativo.Apagado || ativo.Residual {
		t.Fatalf("ativo mal lido: %+v", ativo)
	}
	realocado, _ := InterpretarBody("0|/a.txt (deleted-realloc)|70-128-2|r/rrwxrwxrwx|0|0|9|1|1|1|1")
	if realocado.Apagado || !realocado.Residual {
		t.Fatalf("metadados de outro arquivo nao podem valer para este nome: %+v", realocado)
	}
	barra, ok := InterpretarBody("0|/a|b.txt|5-128-1|r/rrwxrwxrwx|0|0|9|1|1|1|1")
	if !ok || barra.Caminho != "/a|b.txt" {
		t.Fatalf("nome com barra vertical: %+v", barra)
	}
	if _, ok := InterpretarBody("linha estranha"); ok {
		t.Fatal("linha invalida aceita")
	}
}

func TestRegistrosDeApagadoNaoAfirmamHoraDaExclusao(t *testing.T) {
	e, _ := InterpretarBody("0|/Bunda.txt (deleted)|65-128-2|-/rrwxrwxrwx|48|0|4296|915264240|951848040|1328281979|1328281801")
	rs := Registros(e, 61)
	if len(rs) != 4 {
		t.Fatalf("esperava 4 registros, veio %d", len(rs))
	}
	ultimo := rs[3]
	if !strings.Contains(ultimo.Descricao, "momento desconhecido") {
		t.Fatalf("texto sugere hora da exclusao: %s", ultimo.Descricao)
	}
	if ultimo.Quando != "2012-02-03T15:12:59Z" {
		t.Fatalf("data errada: %s", ultimo.Quando)
	}
	nome, _ := InterpretarBody("0|/Bunda.txt ($FILE_NAME) (deleted)|65-48-3|-/rrwxrwxrwx|48|0|84|1|1|1|1")
	if len(Registros(nome, 61)) != 0 {
		t.Fatal("$FILE_NAME nao deveria duplicar a timeline")
	}
}

func TestTextoLegivel(t *testing.T) {
	casos := []struct {
		nome    string
		dados   []byte
		esperar string
		ok      bool
	}{
		{"utf-8", []byte("usuário=Ana\n"), "usuário=Ana\n", true},
		{"latin-1", []byte{'c', 'a', 'f', 0xE9}, "café", true},
		{"utf-16", []byte{0xFF, 0xFE, 'o', 0, 'i', 0}, "oi", true},
		{"binario", []byte{0, 1, 2, 3, 4, 5, 'a'}, "", false},
		{"vazio", nil, "", false},
	}
	for _, c := range casos {
		obtido, ok := TextoLegivel(c.dados)
		if ok != c.ok || obtido != c.esperar {
			t.Errorf("%s: obtido %q %v", c.nome, obtido, ok)
		}
	}
}

func TestAgruparSegmentos(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"0/disco.E02", "1/disco.E01", "2/outro.dd", "3/parte.002", "4/parte.001"} {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	grupos, err := Agrupar(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(grupos) != 3 {
		t.Fatalf("grupos errados: %v", grupos)
	}
	if filepath.Base(grupos[0][0]) != "disco.E01" || filepath.Base(grupos[0][1]) != "disco.E02" {
		t.Fatalf("ordem dos segmentos: %v", grupos[0])
	}
}
