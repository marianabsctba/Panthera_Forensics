// Panthera Forensics: abrir o executavel, arrastar a evidencia, investigar.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/marianabsctba/Panthera_Forensics/internal/caso"
	"github.com/marianabsctba/Panthera_Forensics/internal/disco"
	"github.com/marianabsctba/Panthera_Forensics/internal/modulo"
	"github.com/marianabsctba/Panthera_Forensics/internal/motor"
	"github.com/marianabsctba/Panthera_Forensics/internal/processo"
	"github.com/marianabsctba/Panthera_Forensics/internal/relatorio"
	"github.com/marianabsctba/Panthera_Forensics/internal/web"
	"github.com/marianabsctba/Panthera_Forensics/modulos"
)

func main() {
	processo.UsarConsoleDoPai()
	if err := executar(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}

// pastaBase e a pasta ao lado do executavel, ou a indicada em PANTHERA_HOME.
func pastaBase() (string, error) {
	if h := os.Getenv("PANTHERA_HOME"); h != "" {
		return h, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

func carregarMotor(base string) (*motor.Motor, error) {
	embutidos, err := modulo.CarregarFS(modulos.Embutidos)
	if err != nil {
		return nil, err
	}
	locais, err := modulo.CarregarPasta(filepath.Join(base, "modulos"))
	if err != nil {
		return nil, err
	}
	if err := modulos.GravarRegras(filepath.Join(base, "regras")); err != nil {
		return nil, err
	}
	return &motor.Motor{Modulos: modulo.Combinar(embutidos, locais), DirFerramentas: filepath.Join(base, "ferramentas")}, nil
}

func executar(args []string) error {
	base, err := pastaBase()
	if err != nil {
		return err
	}
	m, err := carregarMotor(base)
	if err != nil {
		return err
	}
	dirCasos := filepath.Join(base, "casos")
	if len(args) == 0 {
		return abrir(dirCasos, m, 7878, true)
	}
	ctx := context.Background()
	switch args[0] {
	case "auxiliar-disco":
		f := flag.NewFlagSet("auxiliar-disco", flag.ExitOnError)
		dirBin := f.String("bin", "", "pasta dos executaveis do The Sleuth Kit")
		dirSaida := f.String("saida", "", "pasta de saida do modulo")
		f.Parse(args[1:])
		if f.NArg() != 1 || *dirBin == "" || *dirSaida == "" {
			return fmt.Errorf("uso: auxiliar-disco -bin <pasta> -saida <pasta> <entrada>")
		}
		return disco.Executar(*dirBin, f.Arg(0), *dirSaida)
	case "abrir":
		f := flag.NewFlagSet("abrir", flag.ExitOnError)
		porta := f.Int("porta", 7878, "porta local")
		semNavegador := f.Bool("sem-navegador", false, "nao abrir o navegador")
		f.Parse(args[1:])
		return abrir(dirCasos, m, *porta, !*semNavegador)
	case "preparar":
		return web.InstalarTodos(ctx, m.Modulos, m.DirFerramentas)
	case "aprofundar":
		if len(args) != 2 {
			return fmt.Errorf("uso: aprofundar <pasta do caso>")
		}
		if err := web.InstalarOpcionais(ctx, m.Modulos, m.DirFerramentas); err != nil {
			return err
		}
		c, err := caso.Abrir(args[1])
		if err != nil {
			return err
		}
		defer c.Fechar()
		res, err := m.Variante(false, true).Processar(ctx, c, func(etapa string, feitas, total int) {
			if etapa != "" {
				fmt.Printf("[%d/%d] %s\n", feitas+1, total, etapa)
			}
		})
		if err != nil {
			return err
		}
		fmt.Printf("executadas=%d reutilizadas=%d falhas=%d ausentes=%d sem_leitura=%d\n", res.Executadas, res.Reutilizadas, len(res.Falhas), len(res.Ausentes), res.SemModulo)
		for _, falha := range res.Falhas {
			fmt.Println("falha:", falha)
		}
		return nil
	case "modulos":
		for _, md := range m.Modulos {
			fmt.Printf("%-24s %-12s %s\n", md.Nome, md.Versao, md.Titulo)
		}
		return nil
	case "novo":
		f := flag.NewFlagSet("novo", flag.ExitOnError)
		numero := f.String("numero", "", "numero do processo")
		perito := f.String("perito", "", "responsavel")
		f.Parse(args[1:])
		if f.NArg() != 1 {
			return fmt.Errorf("uso: novo [-numero N] [-perito P] <nome>")
		}
		c, err := caso.Criar(dirCasos, f.Arg(0), *numero, *perito)
		if err != nil {
			return err
		}
		defer c.Fechar()
		fmt.Println(c.Dir)
		return nil
	case "processar":
		if len(args) < 3 {
			return fmt.Errorf("uso: processar <pasta do caso> <arquivo ou pasta>...")
		}
		c, err := caso.Abrir(args[1])
		if err != nil {
			return err
		}
		defer c.Fechar()
		for _, caminho := range args[2:] {
			if _, err := c.AdicionarCaminho(caminho); err != nil {
				return err
			}
		}
		res, err := m.Processar(ctx, c, func(etapa string, feitas, total int) {
			if etapa != "" {
				fmt.Printf("[%d/%d] %s\n", feitas+1, total, etapa)
			}
		})
		if err != nil {
			return err
		}
		fmt.Printf("executadas=%d reutilizadas=%d falhas=%d ausentes=%d sem_leitura=%d\n", res.Executadas, res.Reutilizadas, len(res.Falhas), len(res.Ausentes), res.SemModulo)
		for _, falha := range res.Falhas {
			fmt.Println("falha:", falha)
		}
		return nil
	case "verificar":
		if len(args) != 2 {
			return fmt.Errorf("uso: verificar <pasta do caso>")
		}
		c, err := caso.Abrir(args[1])
		if err != nil {
			return err
		}
		defer c.Fechar()
		conf, err := c.Verificar()
		if err != nil {
			return err
		}
		ruins := 0
		for _, x := range conf {
			if !x.Integra {
				ruins++
				fmt.Printf("PROBLEMA %s: %s\n", x.Evidencia.Nome, x.Problema)
			}
		}
		fmt.Printf("%d evidencia(s), %d com problema\n", len(conf), ruins)
		if ruins > 0 {
			return fmt.Errorf("integridade comprometida")
		}
		return nil
	case "relatorio":
		if len(args) != 2 {
			return fmt.Errorf("uso: relatorio <pasta do caso>")
		}
		c, err := caso.Abrir(args[1])
		if err != nil {
			return err
		}
		defer c.Fechar()
		caminho, err := relatorio.Salvar(c)
		if err != nil {
			return err
		}
		fmt.Println(caminho)
		return nil
	}
	return fmt.Errorf("comando desconhecido: %s", args[0])
}

func abrir(dirCasos string, m *motor.Motor, porta int, navegador bool) error {
	if err := os.MkdirAll(dirCasos, 0o755); err != nil {
		return err
	}
	s, err := web.Novo(dirCasos, m)
	if err != nil {
		return err
	}
	l, err := web.Escutar(porta)
	if err != nil {
		return err
	}
	endereco := l.Addr().String()
	url := "http://" + endereco + "/"
	fmt.Println("Panthera Forensics aberto em", url)
	if navegador {
		abrirNavegador(url)
	}
	s.AoEncerrar = func() {
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}
	return http.Serve(l, s.Handler(endereco))
}

func abrirNavegador(url string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		c = exec.Command("open", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	_ = processo.Ocultar(c).Start()
}
