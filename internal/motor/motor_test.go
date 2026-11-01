package motor

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/internal/custodia"
	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
)

const manifestoFalso = `
contrato: 1
nome: falso
titulo: Leitura de teste
versao: "1.0"
reconhece:
  - tipo: teste
    magica_hex: "46414b45"
consome: [teste]
comando:
  ` + runtime.GOOS + `:
    exec: falso*
    args: ["{entrada}", "{saida}"]
saida:
  arquivos: "*.csv"
  formato: csv
  severidades: {crit: critica, high: alta}
  mapas:
    - tipo: alerta
      quando: "{Hora}"
      descricao: "{Regra}"
      severidade: "{Nivel}"
      origem_local: "{Pos}"
      entidades:
        - {tipo: host, valor: "{Host}"}
`

func montar(t *testing.T) (*Motor, *caso.Caso) {
	t.Helper()
	dirModulo := t.TempDir()
	saida := filepath.Join(dirModulo, "falso")
	if runtime.GOOS == "windows" {
		saida += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", saida, "./testdata/falso")
	if s, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, s)
	}
	md, err := modulo.Interpretar([]byte(manifestoFalso))
	if err != nil {
		t.Fatal(err)
	}
	md.Dir = dirModulo
	c, err := caso.Criar(t.TempDir(), "Caso de teste", "IP 1/2026", "perita")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Fechar() })
	return &Motor{Modulos: []*modulo.Manifesto{md}, DirFerramentas: t.TempDir()}, c
}

func adicionar(t *testing.T, c *caso.Caso, nome, conteudo string) {
	t.Helper()
	if _, err := c.Adicionar(strings.NewReader(conteudo), nome, "teste/"+nome); err != nil {
		t.Fatal(err)
	}
}

func TestFluxoCompleto(t *testing.T) {
	m, c := montar(t)
	// A extensao mente: quem decide o tipo e a assinatura.
	adicionar(t, c, "foto.jpg", "FAKE conteudo")
	adicionar(t, c, "desconhecido.bin", "outra coisa")

	res, err := m.Processar(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Executadas != 1 || len(res.Falhas) != 0 || res.SemModulo != 1 {
		t.Fatalf("resultado inesperado: %+v", res)
	}

	resumo, err := c.Resumir()
	if err != nil {
		t.Fatal(err)
	}
	// Os dois alertas e o arquivo sem leitura propria, que tambem precisa aparecer.
	if resumo.Registros != 3 || resumo.Alertas["critica"] != 1 || resumo.Alertas["alta"] != 1 {
		t.Fatalf("resumo inesperado: %+v", resumo)
	}

	achados, err := c.Consultar(caso.Filtro{Tipo: "alerta", Ordem: "gravidade"})
	if err != nil {
		t.Fatal(err)
	}
	if achados[0].Descricao != "Log limpo" {
		t.Fatalf("mais grave deveria vir primeiro: %+v", achados[0])
	}

	// PC-01 e pc-01 precisam virar a mesma entidade, ligando os dois registros.
	entidades, err := c.Entidades("host", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entidades) != 1 || entidades[0].Registros != 2 {
		t.Fatalf("entidades nao unificadas: %+v", entidades)
	}

	achou, err := c.Consultar(caso.Filtro{Texto: "limpo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(achou) != 1 {
		t.Fatalf("busca devolveu %d", len(achou))
	}
	detalhe, err := c.Detalhe(achou[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if detalhe.OrigemArquivo != "foto.jpg (evidência 1)" {
		t.Fatalf("origem nao aponta para a evidencia: %q", detalhe.OrigemArquivo)
	}
	if detalhe.OrigemLocal != "20" || !bytes.Contains(detalhe.Dados, []byte("Log limpo")) || len(detalhe.Entidades) != 1 {
		t.Fatalf("origem ou dados originais perdidos: %+v", detalhe)
	}

	conf, err := c.Verificar()
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range conf {
		if !x.Integra {
			t.Fatalf("evidencia nao integra: %+v", x)
		}
	}
	verificarCustodia(t, c, "modulo.executado")
}

func TestNaoRepeteMesmaTarefa(t *testing.T) {
	m, c := montar(t)
	adicionar(t, c, "a.bin", "FAKE a")
	if _, err := m.Processar(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	res, err := m.Processar(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Executadas != 0 || res.Reutilizadas != 1 {
		t.Fatalf("deveria reaproveitar: %+v", res)
	}
	if r, _ := c.Resumir(); r.Registros != 2 {
		t.Fatalf("registros duplicados: %d", r.Registros)
	}
}

func TestBuscaAchaParteDoCaminhoEValoresTecnicos(t *testing.T) {
	_, c := montar(t)
	res, err := c.DB.Exec(`INSERT INTO execucoes(chave,modulo,titulo,versao,estado,inicio) VALUES('k','m','t','1','concluida','agora')`)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := res.LastInsertId()
	descricao := `Arquivo criado: /Documents and Settings/Mr. Evil/interception 192.168.1.111 N-1A9ODN6ZXK4LQ aee4fcd9`
	res, err = c.DB.Exec(`INSERT INTO registros(execucao_id,tipo,descricao) VALUES(?,'evento',?)`, x, descricao)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	if _, err := c.DB.Exec(`INSERT INTO busca(rowid,descricao,fonte,dados) VALUES(?,?,'','{}')`, id, descricao); err != nil {
		t.Fatal(err)
	}
	for _, termo := range []string{"interception", "INTERCEPTION", "Mr. Evil/interception", "192.168.1.111", "N-1A9ODN6ZXK4LQ", "aee4fcd9"} {
		achou, err := c.Consultar(caso.Filtro{Texto: termo})
		if err != nil {
			t.Fatalf("%s: %v", termo, err)
		}
		if len(achou) != 1 {
			t.Errorf("busca por %q devolveu %d", termo, len(achou))
		}
	}
	if achou, _ := c.Consultar(caso.Filtro{Texto: "192.168.1.112"}); len(achou) != 0 {
		t.Error("IP diferente nao deveria ser encontrado")
	}
}

func TestFalhaNaoRepeteSemPedir(t *testing.T) {
	m, c := montar(t)
	adicionar(t, c, "ruim.bin", "FAKE QUEBRAR")
	contar := func() (n int) {
		if err := c.DB.QueryRow(`SELECT COUNT(*) FROM execucoes WHERE estado='falhou'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for i := 0; i < 2; i++ {
		res, err := m.Processar(context.Background(), c, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Falhas) != 1 {
			t.Fatalf("a falha precisa continuar sendo informada: %+v", res)
		}
	}
	if n := contar(); n != 1 {
		t.Fatalf("falha repetida sem pedido: %d", n)
	}
	m.RefazerFalhas = true
	if _, err := m.Processar(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	if n := contar(); n != 2 {
		t.Fatalf("pedido de refazer ignorado: %d", n)
	}
}

func TestModuloOpcionalSoRodaNoExameProfundo(t *testing.T) {
	m, c := montar(t)
	m.Modulos[0].Opcional = true
	adicionar(t, c, "a.bin", "FAKE a")
	res, err := m.Processar(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Executadas != 0 {
		t.Fatalf("opcional rodou na analise padrao: %+v", res)
	}
	m.Profundo = true
	res, err = m.Processar(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Executadas != 1 {
		t.Fatalf("opcional nao rodou no exame profundo: %+v", res)
	}
}

func TestModuloDemoradoSoRodaNaLinhaCompleta(t *testing.T) {
	m, c := montar(t)
	m.Modulos[0].Opcional, m.Modulos[0].Demorado = true, true
	adicionar(t, c, "a.bin", "FAKE a")
	for _, caso := range []struct {
		motor    *Motor
		esperado int
	}{{m, 0}, {m.Variante(false, true), 0}, {m.Completa(), 1}} {
		tarefas, _, err := caso.motor.Planejar(c)
		if err != nil {
			t.Fatal(err)
		}
		if len(tarefas) != caso.esperado {
			t.Fatalf("esperava %d tarefas, veio %d", caso.esperado, len(tarefas))
		}
	}
}

func TestReconhecePrefixoDoNome(t *testing.T) {
	m, _ := montar(t)
	m.Modulos[0].Reconhece = []modulo.Reconhecimento{{Tipo: "lixeira", Prefixos: []string{"$I"}}}
	caminho := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(caminho, []byte("dados"), 0o644); err != nil {
		t.Fatal(err)
	}
	for nome, esperado := range map[string]string{"$IABC123.jpg": "lixeira", "$i9.exe": "lixeira", "I.txt": ""} {
		tipo, err := m.Identificar(caminho, nome)
		if err != nil {
			t.Fatal(err)
		}
		if tipo != esperado {
			t.Fatalf("%s: tipo %q", nome, tipo)
		}
	}
}

func TestDadosMantemTextoOriginal(t *testing.T) {
	m, c := montar(t)
	m.Modulos[0].Saida.Formato = "contrato"
	m.Modulos[0].Saida.Mapas = nil
	dir := t.TempDir()
	saida := filepath.Join(dir, "resultado.csv")
	if err := os.WriteFile(saida, []byte(`{"tipo":"evento","descricao":"x","dados":{"caminho":"/a&b<c>.txt"}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := importar(c, 1, m.Modulos[0], dir, &origens{porCaminho: map[string]string{}}); err == nil {
		// A execucao 1 nao existe: se o banco aceitar, o texto ainda pode ser conferido.
		var d string
		if err := c.DB.QueryRow(`SELECT dados FROM registros LIMIT 1`).Scan(&d); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(d, "/a&b<c>.txt") {
			t.Fatalf("texto escapado: %s", d)
		}
		return
	}
	if _, err := c.DB.Exec(`INSERT INTO execucoes(id,chave,modulo,titulo,versao,estado,inicio) VALUES(1,1,1,1,1,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := importar(c, 1, m.Modulos[0], dir, &origens{porCaminho: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	var d string
	if err := c.DB.QueryRow(`SELECT dados FROM registros LIMIT 1`).Scan(&d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d, "/a&b<c>.txt") {
		t.Fatalf("texto escapado: %s", d)
	}
}

func TestArquivoSemLeituraFicaVisivelENaBusca(t *testing.T) {
	m, c := montar(t)
	adicionar(t, c, "anotacao.dat", "senha do cofre e 1234")
	adicionar(t, c, "binario.dat", "\x00\x01\x02\x03\x04\x05\x06\x07")
	if _, err := m.Processar(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	if r, _ := c.Resumir(); r.Registros != 2 {
		t.Fatalf("todo arquivo precisa aparecer: %+v", r)
	}
	achou, err := c.Consultar(caso.Filtro{Texto: "cofre"})
	if err != nil || len(achou) != 1 {
		t.Fatalf("texto fora da busca: %+v %v", achou, err)
	}
	if _, err := m.Processar(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	if r, _ := c.Resumir(); r.Registros != 2 {
		t.Fatalf("listou de novo o que ja estava listado: %d", r.Registros)
	}
	verificarCustodia(t, c, "arquivos.listados")
	conteudo, total, err := m.LerArquivo(context.Background(), c, achou[0].ID, 0)
	if err != nil || total != 21 || string(conteudo) != "senha do cofre e 1234" {
		t.Fatalf("conteudo do cofre: %q %d %v", conteudo, total, err)
	}
}

func zipCom(t *testing.T, itens map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for nome, dados := range itens {
		w, err := z.Create(nome)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(dados)
	}
	z.Close()
	return b.Bytes()
}

func TestEvidenciaRemovidaPeloAntivirusNaoParaOsOutros(t *testing.T) {
	m, c := montar(t)
	adicionar(t, c, "bom.bin", "FAKE bom")
	adicionar(t, c, "removido.dat", "conteudo que o antivirus removeu")
	todas, err := c.Evidencias()
	if err != nil {
		t.Fatal(err)
	}
	caminho := c.CaminhoEvidencia(todas[1].SHA256)
	if err := os.Chmod(caminho, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(caminho); err != nil {
		t.Fatal(err)
	}
	res, err := m.Processar(context.Background(), c, nil)
	if err != nil {
		t.Fatalf("um arquivo removido nao pode parar o processamento: %v", err)
	}
	if res.Executadas != 1 {
		t.Fatalf("o arquivo bom deveria ser lido: %+v", res)
	}
	alertas, err := c.Consultar(caso.Filtro{Severidade: "alta", Texto: "antivírus"})
	if err != nil || len(alertas) != 1 || !strings.Contains(alertas[0].Descricao, "removido.dat") {
		t.Fatalf("sem alerta da evidencia removida: %+v %v", alertas, err)
	}
	conf, err := c.Verificar()
	if err != nil {
		t.Fatal(err)
	}
	if conf[1].Integra || !conf[0].Integra {
		t.Fatalf("conferencia errada: %+v", conf)
	}
	if _, err := m.Processar(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	if todos, _ := c.Consultar(caso.Filtro{Texto: "antivírus"}); len(todos) != 1 {
		t.Fatalf("alerta repetido: %d", len(todos))
	}
}

func TestExecucaoInterrompidaNaoFicaRodandoParaSempre(t *testing.T) {
	m, c := montar(t)
	if _, err := c.DB.Exec(`INSERT INTO execucoes(chave,modulo,titulo,versao,estado,inicio) VALUES('k','falso','Leitura','1','rodando','agora')`); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Processar(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	var estado, erro string
	if err := c.DB.QueryRow(`SELECT estado,erro FROM execucoes WHERE chave='k'`).Scan(&estado, &erro); err != nil {
		t.Fatal(err)
	}
	if estado != "falhou" || !strings.Contains(erro, "interrompida") {
		t.Fatalf("estado %s, erro %s", estado, erro)
	}
	verificarCustodia(t, c, "modulo.interrompido")
}

func TestZipDentroDeZip(t *testing.T) {
	m, c := montar(t)
	dentro := zipCom(t, map[string][]byte{"pasta/nota.txt": []byte("achado dentro do segundo pacote")})
	fora := zipCom(t, map[string][]byte{"dentro.zip": dentro})
	if _, err := c.Adicionar(bytes.NewReader(fora), "fora.zip", "fora.zip"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Processar(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	achou, err := c.Consultar(caso.Filtro{Texto: "segundo pacote"})
	if err != nil || len(achou) != 1 {
		t.Fatalf("zip aninhado nao lido: %+v %v", achou, err)
	}
	if !strings.Contains(achou[0].Descricao, "fora.zip!dentro.zip!pasta/nota.txt") {
		t.Fatalf("caminho perdido: %s", achou[0].Descricao)
	}
}

func TestZipCorrompidoPreservaEAvisa(t *testing.T) {
	_, c := montar(t)
	novas, err := c.Adicionar(strings.NewReader("PK\x03\x04 nao e um zip de verdade"), "ruim.zip", "ruim.zip")
	if err == nil || !strings.Contains(err.Error(), "corrompido") {
		t.Fatalf("erro sem explicacao: %v", err)
	}
	if len(novas) != 1 {
		t.Fatalf("o arquivo enviado precisa ficar preservado: %+v", novas)
	}
}

func TestAgruparSegmentosDeImagem(t *testing.T) {
	grupos := agruparSegmentos([]caso.Evidencia{
		{ID: 1, Nome: "disco.E02"}, {ID: 2, Nome: "disco.E01"}, {ID: 3, Nome: "outro.dd"},
		{ID: 4, Nome: "parte.002"}, {ID: 5, Nome: "parte.001"},
	})
	if len(grupos) != 3 {
		t.Fatalf("grupos errados: %+v", grupos)
	}
	if grupos[0][0].Nome != "disco.E01" || grupos[2][0].Nome != "parte.001" {
		t.Fatalf("a primeira parte precisa vir primeiro: %+v", grupos)
	}
}

func TestCaminhoWSL(t *testing.T) {
	if c := caminhoWSL(`D:\Casos\a b\c.pcap`); c != "/mnt/d/Casos/a b/c.pcap" {
		t.Fatalf("caminho errado: %s", c)
	}
}

func TestIgnorarDerivados(t *testing.T) {
	m, c := montar(t)
	m.Modulos[0].IgnorarDerivados = true
	direta, err := c.Adicionar(strings.NewReader("FAKE direta"), "a.bin", "teste/a.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AdicionarDerivado(strings.NewReader("FAKE derivada"), "b.bin", "a.bin!b.bin", direta[0].ID); err != nil {
		t.Fatal(err)
	}
	tarefas, _, err := m.Planejar(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(tarefas) != 1 || tarefas[0].Entradas[0].Nome != "a.bin" {
		t.Fatalf("derivada nao deveria entrar: %+v", tarefas)
	}
}

func TestMesmaPastaJuntaArquivosDaOrigem(t *testing.T) {
	historico := caso.Evidencia{ID: 1, Nome: "History", Origem: `D:\perfil\Default\History`}
	todas := []caso.Evidencia{
		historico,
		{ID: 2, Nome: "Cookies", Origem: `D:\perfil\Default\Cookies`},
		{ID: 3, Nome: "Cookies", Origem: `D:\perfil\Default\Cookies`},
		{ID: 4, Nome: "History", Origem: `D:\outro\History`},
	}
	grupo := mesmaPasta(historico, todas)
	if len(grupo) != 2 || grupo[0].ID != 1 || grupo[1].ID != 2 {
		t.Fatalf("grupo errado: %+v", grupo)
	}
}

func TestFalhaFicaRegistradaESemDadosParciais(t *testing.T) {
	m, c := montar(t)
	adicionar(t, c, "ruim.bin", "FAKE QUEBRAR")
	adicionar(t, c, "bom.bin", "FAKE bom")
	res, err := m.Processar(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Falhas) != 1 || res.Executadas != 1 {
		t.Fatalf("uma falha nao deveria parar o resto: %+v", res)
	}
	if r, _ := c.Resumir(); r.ExecucoesErro != 1 || r.Registros != 2 {
		t.Fatalf("resumo inesperado: %+v", r)
	}
	verificarCustodia(t, c, "modulo.falhou")
}

func TestPacoteZipViraEvidenciasFilhas(t *testing.T) {
	m, c := montar(t)
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	// Nome hostil: nao pode escapar da pasta do caso.
	w, err := z.Create("../../fora.bin")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("FAKE dentro do pacote"))
	z.Close()
	if _, err := c.Adicionar(&buf, "coleta.zip", "teste/coleta.zip"); err != nil {
		t.Fatal(err)
	}
	todas, err := c.Evidencias()
	if err != nil {
		t.Fatal(err)
	}
	if len(todas) != 2 || todas[1].PaiID == nil || todas[1].Nome != "fora.bin" {
		t.Fatalf("filhas inesperadas: %+v", todas)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(c.Dir), "fora.bin")); err == nil {
		t.Fatal("arquivo escapou da pasta do caso")
	}
	res, err := m.Processar(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Executadas != 1 {
		t.Fatalf("filha nao processada: %+v", res)
	}
}

func TestDetectaEvidenciaAlterada(t *testing.T) {
	_, c := montar(t)
	adicionar(t, c, "a.bin", "FAKE original")
	todas, _ := c.Evidencias()
	caminho := c.CaminhoEvidencia(todas[0].SHA256)
	if err := os.Chmod(caminho, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caminho, []byte("FAKE alterado"), 0o644); err != nil {
		t.Fatal(err)
	}
	conf, err := c.Verificar()
	if err != nil {
		t.Fatal(err)
	}
	if conf[0].Integra {
		t.Fatal("alteracao nao detectada")
	}
}

func TestModuloAusenteFicaNaCustodia(t *testing.T) {
	m, c := montar(t)
	m.Modulos[0].Dir = t.TempDir()
	adicionar(t, c, "a.bin", "FAKE a")
	res, err := m.Processar(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ausentes) != 1 {
		t.Fatalf("modulo ausente nao informado: %+v", res)
	}
	verificarCustodia(t, c, "modulo.nao_executado")
}

func verificarCustodia(t *testing.T, c *caso.Caso, acao string) {
	t.Helper()
	entradas, err := custodia.Ler(filepath.Join(c.Dir, "custodia.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := custodia.Verificar(entradas); err != nil {
		t.Fatal(err)
	}
	for _, e := range entradas {
		if e.Acao == acao {
			return
		}
	}
	t.Fatalf("acao %s nao encontrada na custodia", acao)
}
