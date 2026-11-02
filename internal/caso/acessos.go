package caso

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// filtroAcessos e igual na consulta e no indice parcial, porque o SQLite so usa o indice
// quando o texto da condicao coincide.
const filtroAcessos = `fonte IN ('Security','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational','System')`

// Limites do que vai para a tela. O total real sempre acompanha a lista cortada.
const (
	maximoOrigens       = 200
	maximoContas        = 8
	maximoMarcos        = 300
	maximoMarcosOrigens = 50
)

// janelaVizinha e ate onde uma entrada remota ainda e citada ao lado de uma mudanca.
const janelaVizinha = time.Hour

// ContaAcesso e uma conta usada a partir de uma origem.
type ContaAcesso struct {
	Conta    string `json:"conta"`
	Falhas   int64  `json:"falhas"`
	Entradas int64  `json:"entradas"`
}

// OrigemAcesso soma o que os logs dizem sobre um IP ou uma estacao remota.
type OrigemAcesso struct {
	Origem          string           `json:"origem"`
	Rede            string           `json:"rede"`
	Estacoes        []string         `json:"estacoes"`
	Contas          []ContaAcesso    `json:"contas"`
	ContasTotal     int              `json:"contas_total"`
	Falhas          int64            `json:"falhas"`
	Entradas        int64            `json:"entradas"`
	Anonimas        int64            `json:"anonimas"`
	RDP             int64            `json:"rdp"`
	Primeira        string           `json:"primeira"`
	Ultima          string           `json:"ultima"`
	PrimeiraEntrada string           `json:"primeira_entrada"`
	ContaEntrada    string           `json:"conta_entrada"`
	FalhasAntes     int64            `json:"falhas_antes"`
	Tipos           map[string]int64 `json:"tipos"`
	Acoes           []string         `json:"acoes"`
	Proximas        []string         `json:"proximas"`
	Registro        int64            `json:"registro"`
}

// MarcoAcesso e um fato para a sequencia do caso, com o registro que o prova.
type MarcoAcesso struct {
	Quando    string `json:"quando"`
	Descricao string `json:"descricao"`
	Origem    string `json:"origem"`
	Registro  int64  `json:"registro"`
}

// Acessos e o resumo dos acessos remotos. Tudo e contagem direta dos logs: quem e
// administrador e quem e invasor continua sendo conclusao do perito.
type Acessos struct {
	Origens      []OrigemAcesso `json:"origens"`
	TotalOrigens int            `json:"total_origens"`
	Marcos       []MarcoAcesso  `json:"marcos"`
	TotalMarcos  int            `json:"total_marcos"`
	Eventos      int64          `json:"eventos"`
	Repetidos    int64          `json:"repetidos"`
	Falhas       int64          `json:"falhas"`
	Entradas     int64          `json:"entradas"`
}

// nomesLogon traduz o LogonType do Windows.
var nomesLogon = map[string]string{
	"2": "no teclado", "3": "pela rede", "4": "tarefa", "5": "serviço", "7": "desbloqueio",
	"8": "pela rede, com senha aberta", "9": "com outra credencial",
	"10": "área de trabalho remota", "11": "com credencial guardada",
}

// eventoAcesso e a parte de um registro que importa para o resumo.
type eventoAcesso struct {
	registro int64
	quando   string
	fonte    string
	id       string
	maquina  string
	numero   string
	campos   map[string]string
}

// linhaAcesso e um registro ainda sem interpretar.
type linhaAcesso struct {
	registro             int64
	quando, fonte, dados string
}

// interpretar devolve falso para o que nao e um evento de acesso.
func (l linhaAcesso) interpretar() (eventoAcesso, bool) {
	var b struct {
		Computer, EventId, EventRecordId, Provider, Payload string
	}
	if json.Unmarshal([]byte(l.dados), &b) != nil || !eventoDoCanal(l.fonte, b.EventId, b.Provider) {
		return eventoAcesso{}, false
	}
	return eventoAcesso{registro: l.registro, quando: l.quando, fonte: l.fonte, id: b.EventId, maquina: b.Computer,
		numero: b.EventRecordId, campos: camposDoEvento(b.Payload)}, true
}

// lerEventosAcesso le os eventos do Windows em paralelo, porque interpretar 100 mil eventos
// leva segundos, e tira as copias: o mesmo log pode entrar mais de uma vez, como quando
// tambem vem de uma copia de sombra.
func (c *Caso) lerEventosAcesso() ([]eventoAcesso, int64, error) {
	linhas, err := c.DB.Query(`SELECT id,quando,fonte,dados FROM registros WHERE ` + filtroAcessos + ` AND quando IS NOT NULL`)
	if err != nil {
		return nil, 0, err
	}
	defer linhas.Close()
	fila := make(chan linhaAcesso, 256)
	partes := make([][]eventoAcesso, runtime.GOMAXPROCS(0))
	var grupo sync.WaitGroup
	for i := range partes {
		grupo.Go(func() {
			for l := range fila {
				if e, ok := l.interpretar(); ok {
					partes[i] = append(partes[i], e)
				}
			}
		})
	}
	var falha error
	for linhas.Next() {
		var l linhaAcesso
		if falha = linhas.Scan(&l.registro, &l.quando, &l.fonte, &l.dados); falha != nil {
			break
		}
		fila <- l
	}
	close(fila)
	grupo.Wait()
	if falha == nil {
		falha = linhas.Err()
	}
	if falha != nil {
		return nil, 0, falha
	}
	eventos := slices.Concat(partes...)
	slices.SortFunc(eventos, func(a, b eventoAcesso) int {
		return cmp.Or(cmp.Compare(a.quando, b.quando), cmp.Compare(a.registro, b.registro))
	})
	vistos := make(map[string]bool, len(eventos))
	var repetidos int64
	unicos := eventos[:0]
	for _, e := range eventos {
		if e.numero != "" {
			chave := e.maquina + "|" + e.fonte + "|" + e.numero
			if vistos[chave] {
				repetidos++
				continue
			}
			vistos[chave] = true
		}
		unicos = append(unicos, e)
	}
	return unicos, repetidos, nil
}

// eventoDoCanal evita confundir numeros: outros programas tambem usam o 4625 ou o 104.
func eventoDoCanal(fonte, id, provedor string) bool {
	switch id {
	case "1149":
		return strings.HasSuffix(fonte, "RemoteConnectionManager/Operational")
	case "104":
		return fonte == "System" && provedor == "Microsoft-Windows-Eventlog"
	case "4624", "4625", "4720", "4726", "4728", "4732", "4756", "1102":
		return fonte == "Security"
	}
	return false
}

// camposDoEvento achata o XML do evento: os nomes sao os do proprio Windows.
func camposDoEvento(payload string) map[string]string {
	campos := map[string]string{}
	var p struct {
		EventData struct {
			Data json.RawMessage
		}
		UserData map[string]map[string]any
	}
	if json.Unmarshal([]byte(payload), &p) != nil {
		return campos
	}
	var lista []struct {
		Nome  string `json:"@Name"`
		Texto any    `json:"#text"`
	}
	if json.Unmarshal(p.EventData.Data, &lista) == nil {
		for _, d := range lista {
			if d.Texto != nil {
				campos[d.Nome] = strings.TrimSpace(fmt.Sprint(d.Texto))
			}
		}
	}
	for _, grupo := range p.UserData {
		for k, v := range grupo {
			if v != nil && !strings.HasPrefix(k, "@") {
				campos[k] = strings.TrimSpace(fmt.Sprint(v))
			}
		}
	}
	return campos
}

// origemRemota devolve de onde veio o acesso, ou vazio se foi na propria maquina.
func origemRemota(ip, estacao, maquina string) (origem, rede string) {
	ip = strings.TrimSpace(ip)
	if ip != "" && ip != "-" {
		if strings.EqualFold(ip, "LOCAL") {
			return "", ""
		}
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return strings.ToUpper(ip), "nome"
		}
		a = a.Unmap()
		switch {
		case a.IsLoopback() || a.IsUnspecified():
			return "", ""
		case a.IsPrivate() || a.IsLinkLocalUnicast():
			return a.String(), "interna"
		}
		return a.String(), "publica"
	}
	estacao = strings.TrimSpace(estacao)
	curto, _, _ := strings.Cut(maquina, ".")
	if estacao == "" || estacao == "-" || strings.EqualFold(estacao, curto) {
		return "", ""
	}
	return strings.ToUpper(estacao), "nome"
}

// somaOrigem acumula uma origem, com os mapas que nao vao para a tela.
type somaOrigem struct {
	OrigemAcesso
	contas   map[string]*ContaAcesso
	estacoes map[string]bool
	acoes    map[string]bool
	proximas map[string]bool
	entrada  int64
}

// entradaRemota e a ultima vez que uma conta entrou de fora.
type entradaRemota struct {
	origem, quando string
}

// intervalo devolve quanto tempo separa duas datas do banco, ou falso se nao der para saber.
func intervalo(antes, depois string) (time.Duration, bool) {
	a, err := time.Parse(time.RFC3339Nano, antes)
	if err != nil {
		return 0, false
	}
	b, err := time.Parse(time.RFC3339Nano, depois)
	if err != nil {
		return 0, false
	}
	return b.Sub(a), true
}

func textoIntervalo(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d s", int(d.Seconds()))
	}
	return fmt.Sprintf("%d min", int(d.Minutes()))
}

func (s *somaOrigem) visto(e eventoAcesso) {
	if s.Primeira == "" {
		s.Primeira, s.Registro = e.quando, e.registro
	}
	s.Ultima = e.quando
}

func (s *somaOrigem) conta(nome string) *ContaAcesso {
	chave := strings.ToLower(nome)
	x := s.contas[chave]
	if x == nil {
		x = &ContaAcesso{Conta: nome}
		s.contas[chave] = x
	}
	return x
}

func (s *somaOrigem) estacao(nome string) {
	if nome != "" && nome != "-" {
		s.estacoes[strings.ToUpper(nome)] = true
	}
}

// Acessos monta o resumo dos acessos remotos e a sequencia dos fatos mais importantes.
func (c *Caso) Acessos() (Acessos, error) {
	a := Acessos{Origens: []OrigemAcesso{}, Marcos: []MarcoAcesso{}}
	eventos, repetidos, err := c.lerEventosAcesso()
	if err != nil {
		return a, err
	}
	a.Eventos, a.Repetidos = int64(len(eventos)), repetidos

	origens := map[string]*somaOrigem{}
	pegar := func(origem, rede string) *somaOrigem {
		s := origens[origem]
		if s == nil {
			s = &somaOrigem{contas: map[string]*ContaAcesso{}, estacoes: map[string]bool{}, acoes: map[string]bool{}, proximas: map[string]bool{}}
			s.Origem, s.Rede, s.Tipos = origem, rede, map[string]int64{}
			origens[origem] = s
		}
		return s
	}
	// Liga a sessao de quem fez uma mudanca ao IP de onde essa sessao entrou.
	sessoes := map[string]string{}
	sessao := func(maquina, id string) string { return maquina + "|" + strings.ToLower(id) }
	// Em um controlador de dominio, a mudanca pode sair em uma sessao antiga do sistema, sem
	// ligacao com o IP. Sobra dizer quem tinha acabado de entrar na conta, sem afirmar autoria.
	ultimas := map[string]entradaRemota{}
	nomesSid := map[string]string{}
	var fatos []MarcoAcesso
	fato := func(e eventoAcesso, sujeito, texto string) {
		origem := sessoes[sessao(e.maquina, e.campos["SubjectLogonId"])]
		descricao := texto + " por " + semNome(sujeito)
		if origem != "" {
			descricao += ", em sessão vinda de " + origem
			origens[origem].acoes[texto] = true
		} else if u, ok := ultimas[strings.ToLower(sujeito)]; ok {
			if d, ok := intervalo(u.quando, e.quando); ok && d <= janelaVizinha {
				descricao += fmt.Sprintf(". Última entrada remota nessa conta: %s, %s antes, o que não prova a autoria", u.origem, textoIntervalo(d))
				origens[u.origem].proximas[texto] = true
			}
		}
		fatos = append(fatos, MarcoAcesso{Quando: e.quando, Descricao: descricao, Origem: origem, Registro: e.registro})
	}

	// O Windows registra a entrada no grupo antes da criacao da conta, no mesmo segundo.
	for _, e := range eventos {
		if e.id == "4720" {
			nomesSid[e.campos["TargetSid"]] = e.campos["TargetUserName"]
		}
	}
	for _, e := range eventos {
		k := e.campos
		switch e.id {
		case "4624", "4625":
			origem, rede := origemRemota(k["IpAddress"], k["WorkstationName"], e.maquina)
			if origem == "" {
				continue
			}
			s := pegar(origem, rede)
			s.visto(e)
			// Em sessao de area de trabalho remota, o campo traz o nome da propria maquina.
			if curto, _, _ := strings.Cut(e.maquina, "."); !strings.EqualFold(k["WorkstationName"], curto) {
				s.estacao(k["WorkstationName"])
			}
			conta := k["TargetUserName"]
			if e.id == "4625" {
				s.Falhas++
				a.Falhas++
				s.conta(semNome(conta)).Falhas++
				continue
			}
			for _, id := range []string{k["TargetLogonId"], k["TargetLinkedLogonId"]} {
				if id != "" && id != "0x0" {
					sessoes[sessao(e.maquina, id)] = origem
				}
			}
			// Sessao anonima abre sem senha nenhuma: nao e entrada em uma conta.
			if strings.EqualFold(conta, "ANONYMOUS LOGON") {
				s.Anonimas++
				continue
			}
			ultimas[strings.ToLower(conta)] = entradaRemota{origem, e.quando}
			s.Entradas++
			a.Entradas++
			s.conta(semNome(conta)).Entradas++
			tipo := nomesLogon[k["LogonType"]]
			if tipo == "" {
				tipo = "tipo " + k["LogonType"]
			}
			s.Tipos[tipo]++
			if s.PrimeiraEntrada == "" {
				s.PrimeiraEntrada, s.ContaEntrada, s.FalhasAntes = e.quando, conta, s.Falhas
				s.entrada = e.registro
			}
		case "1149":
			origem, rede := origemRemota(k["Param3"], "", e.maquina)
			if origem == "" {
				continue
			}
			s := pegar(origem, rede)
			s.visto(e)
			s.RDP++
		case "4720":
			fato(e, k["SubjectUserName"], "Conta "+semNome(k["TargetUserName"])+" criada")
		case "4726":
			fato(e, k["SubjectUserName"], "Conta "+semNome(k["TargetUserName"])+" apagada")
		case "4728", "4732", "4756":
			fato(e, k["SubjectUserName"], nomeDoMembro(k["MemberName"], k["MemberSid"], nomesSid)+" posta no grupo "+semNome(k["TargetUserName"]))
		case "1102":
			fato(e, k["SubjectUserName"], "Log Security limpo")
		case "104":
			fato(e, k["SubjectUserName"], "Log "+semNome(k["Channel"])+" limpo")
		}
	}

	lista := make([]*somaOrigem, 0, len(origens))
	for _, s := range origens {
		s.Estacoes = ordenadas(s.estacoes)
		s.Acoes = ordenadas(s.acoes)
		s.Proximas = ordenadas(s.proximas)
		s.ContasTotal = len(s.contas)
		s.Contas = make([]ContaAcesso, 0, len(s.contas))
		for _, x := range s.contas {
			s.Contas = append(s.Contas, *x)
		}
		slices.SortFunc(s.Contas, func(p, q ContaAcesso) int {
			return cmp.Or(cmp.Compare(q.Entradas, p.Entradas), cmp.Compare(q.Falhas, p.Falhas), cmp.Compare(p.Conta, q.Conta))
		})
		if len(s.Contas) > maximoContas {
			s.Contas = s.Contas[:maximoContas]
		}
		lista = append(lista, s)
	}
	slices.SortFunc(lista, func(p, q *somaOrigem) int {
		return cmp.Or(cmp.Compare(pesoOrigem(p), pesoOrigem(q)),
			cmp.Compare(q.Falhas+q.Entradas, p.Falhas+p.Entradas), cmp.Compare(p.Origem, q.Origem))
	})
	a.TotalOrigens = len(lista)
	for i, s := range lista {
		if i < maximoOrigens {
			a.Origens = append(a.Origens, s.OrigemAcesso)
		}
		if i < maximoMarcosOrigens && s.Rede != "interna" && s.PrimeiraEntrada != "" {
			fatos = append(fatos, MarcoAcesso{Quando: s.PrimeiraEntrada, Origem: s.Origem, Registro: s.entrada,
				Descricao: fmt.Sprintf("Primeira entrada de %s, na conta %s", s.Origem, semNome(s.ContaEntrada))})
		}
	}
	tarefas, err := c.tarefasSuspeitas()
	if err != nil {
		return a, err
	}
	fatos = append(fatos, tarefas...)
	slices.SortStableFunc(fatos, func(p, q MarcoAcesso) int { return cmp.Compare(p.Quando, q.Quando) })
	a.TotalMarcos = len(fatos)
	// Corta os mais antigos: mudancas de instalacao vem antes do que interessa.
	if len(fatos) > maximoMarcos {
		fatos = fatos[len(fatos)-maximoMarcos:]
	}
	a.Marcos = append(a.Marcos, fatos...)
	return a, nil
}

func (c *Caso) tarefasSuspeitas() ([]MarcoAcesso, error) {
	linhas, err := c.DB.Query(`SELECT id,COALESCE(quando,''),descricao FROM registros WHERE tipo='alerta' AND fonte='Tarefa agendada'`)
	if err != nil {
		return nil, err
	}
	defer linhas.Close()
	var saida []MarcoAcesso
	for linhas.Next() {
		var m MarcoAcesso
		if err := linhas.Scan(&m.Registro, &m.Quando, &m.Descricao); err != nil {
			return nil, err
		}
		saida = append(saida, m)
	}
	return saida, linhas.Err()
}

// pesoOrigem ordena por fatos, e nao por suspeita: primeiro quem tem mudancas na maquina
// ligadas a sessao ou logo depois de entrar.
func pesoOrigem(s *somaOrigem) int {
	switch {
	case len(s.acoes) > 0:
		return 0
	case len(s.proximas) > 0:
		return 1
	case s.Rede == "interna":
		return 5
	case s.Entradas > 0 && s.Rede == "publica":
		return 2
	case s.Entradas > 0:
		return 3
	}
	return 4
}

func semNome(nome string) string {
	if nome == "" || nome == "-" {
		return "(sem nome)"
	}
	return nome
}

// nomeDoMembro prefere o nome da conta, que o SID liga ao resto do log. Sem ele, tira o nome
// de "CN=Ana Silva,CN=Users,DC=x", que e o nome de exibicao, ou mostra o proprio SID.
func nomeDoMembro(nome, sid string, nomesSid map[string]string) string {
	if n := nomesSid[sid]; n != "" && sid != "" {
		return n
	}
	if len(nome) > 3 && strings.EqualFold(nome[:3], "CN=") {
		curto, _, _ := strings.Cut(nome[3:], ",")
		return curto
	}
	if nome != "" && nome != "-" {
		return nome
	}
	return semNome(sid)
}

func ordenadas(conjunto map[string]bool) []string {
	saida := make([]string, 0, len(conjunto))
	for v := range conjunto {
		saida = append(saida, v)
	}
	slices.Sort(saida)
	return saida
}
