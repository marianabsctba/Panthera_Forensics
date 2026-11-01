package instalador

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/marianabsctba/Panthera_Forensics/internal/processo"
)

// DistribuicaoWSL e o ambiente Linux dedicado. Tudo fica nele, sem tocar em outras
// distribuicoes nem na configuracao global do WSL.
const DistribuicaoWSL = "panthera-forense"

const (
	imagemWSL     = "https://cloud-images.ubuntu.com/wsl/releases/24.04/current/ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz"
	imagemWSLHash = "8251e27ffff381a4af5f41dcb94d867de3e0d9774a9241908ab34555d99315ea"
)

// wslConf e resolvConf contornam o DNS do WSL, que pode nao responder em algumas
// maquinas, usando resolvedores publicos so nesta distribuicao.
const ajusteRede = `printf '[boot]\nsystemd=false\n[network]\ngenerateResolvConf=false\n' > /etc/wsl.conf
rm -f /etc/resolv.conf
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
`

func wslExiste(ctx context.Context) bool {
	saida, err := processo.Ocultar(exec.CommandContext(ctx, "wsl.exe", "-l", "-q")).Output()
	if err != nil {
		return false
	}
	// A lista vem em UTF-16: tirar os zeros basta para comparar um nome ASCII.
	texto := string(bytes.ReplaceAll(saida, []byte{0}, nil))
	for _, linha := range strings.Split(texto, "\n") {
		if strings.TrimSpace(linha) == DistribuicaoWSL {
			return true
		}
	}
	return false
}

func noWSL(ctx context.Context, script string) error {
	c := processo.Ocultar(exec.CommandContext(ctx, "wsl.exe", "-d", DistribuicaoWSL, "-u", "root", "--", "bash", "-s"))
	c.Stdin = strings.NewReader(script)
	saida, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, ultimasLinhas(string(bytes.ReplaceAll(saida, []byte{0}, nil)), 4))
	}
	return nil
}

func ultimasLinhas(texto string, n int) string {
	linhas := strings.Split(strings.TrimSpace(texto), "\n")
	if len(linhas) > n {
		linhas = linhas[len(linhas)-n:]
	}
	return strings.Join(linhas, " ")
}

// WSLPreparado diz se o ambiente Linux ja foi preparado nesta pasta.
func WSLPreparado(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".instalado"))
	return err == nil
}

// PrepararWSL cria a distribuicao dedicada, se faltar, e instala as ferramentas dela.
// Rodar de novo sem necessidade so reinstala o que estiver faltando.
func PrepararWSL(ctx context.Context, dir, script string) error {
	marca := filepath.Join(dir, ".instalado")
	if _, err := os.Stat(marca); err == nil && wslExiste(ctx) {
		return nil
	}
	if _, err := exec.LookPath("wsl.exe"); err != nil {
		return fmt.Errorf("o WSL não está disponível: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if !wslExiste(ctx) {
		imagem, err := Baixar(ctx, imagemWSL, imagemWSLHash, dir)
		if err != nil {
			return err
		}
		defer os.Remove(imagem)
		saida, err := processo.Ocultar(exec.CommandContext(ctx, "wsl.exe", "--import", DistribuicaoWSL, filepath.Join(dir, "disco"), imagem, "--version", "2")).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ao criar o ambiente Linux: %w: %s", err, bytes.ReplaceAll(saida, []byte{0}, nil))
		}
		if err := noWSL(ctx, ajusteRede); err != nil {
			return err
		}
		if err := processo.Ocultar(exec.CommandContext(ctx, "wsl.exe", "--terminate", DistribuicaoWSL)).Run(); err != nil {
			return err
		}
	}
	if err := noWSL(ctx, script); err != nil {
		return fmt.Errorf("ao instalar as ferramentas no ambiente Linux: %w", err)
	}
	return os.WriteFile(marca, []byte(imagemWSLHash+"\n"), 0o644)
}
