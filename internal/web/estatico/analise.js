"use strict";
// Graficos, filtros e marcacoes. Como no resto da tela, todo valor vem da evidencia e
// entra como texto, nunca como HTML.

const SVG = "http://www.w3.org/2000/svg";

function svg(tag, attrs, ...filhos) {
  const n = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v != null) n.setAttribute(k, v);
  }
  for (const f of filhos.flat()) {
    if (f != null && f !== false) n.append(f instanceof Node ? f : document.createTextNode(String(f)));
  }
  return n;
}

const formatoNumero = (n) => Number(n).toLocaleString("pt-BR");
const nomesEscala = { minuto: "por minuto", hora: "por hora", dia: "por dia", mes: "por mês", ano: "por ano" };

function periodoLegivel(p) {
  return p.replace("T", " ") + (p.length === 13 ? "h" : "");
}

// Barra com o topo arredondado e a base apoiada na linha zero.
function caminhoBarra(x, y, l, a) {
  const r = Math.min(4, l / 2, a);
  return `M${x},${y + a}V${y + r}Q${x},${y} ${x + r},${y}H${x + l - r}Q${x + l},${y} ${x + l},${y + r}V${y + a}Z`;
}

// Atividade no tempo: dois paineis no mesmo eixo, em vez de duas cores na mesma barra,
// porque rosa e cinza nao se separam para quem tem deuteranopia. Clicar amplia o periodo.
async function desenharGrafico(alvo, base, filtro, aoEscolher) {
  const q = new URLSearchParams(filtro);
  q.delete("ordem");
  let dados;
  try { dados = await api(`${base}/atividade?${q}`); } catch { alvo.replaceChildren(); return; }
  if (!dados.baldes.length) { alvo.replaceChildren(); return; }

  const area = el("div", { class: "grafico-area" });
  const dica = el("div", { class: "dica oculto", role: "status" });
  const tabela = el("div", { class: "tabela oculto" }, el("table", {},
    el("thead", {}, el("tr", {}, el("th", {}, "Período"), el("th", {}, "Registros"), el("th", {}, "Alertas"))),
    el("tbody", {}, dados.baldes.filter((b) => b.total > 0).map((b) => el("tr", {},
      el("td", { class: "data" }, periodoLegivel(b.periodo)), el("td", {}, formatoNumero(b.total)), el("td", {}, formatoNumero(b.alertas)))))));
  const botaoTabela = el("button", {
    onclick: () => {
      const oculta = tabela.classList.toggle("oculto");
      botaoTabela.textContent = oculta ? "Ver como tabela" : "Ocultar tabela";
    },
  }, "Ver como tabela");
  const voltar = filtro.de && el("button", { onclick: () => aoEscolher("") }, "Ver todo o período");
  alvo.replaceChildren(el("div", { class: "painel grafico" },
    el("div", { class: "grafico-topo" },
      el("div", {},
        el("h2", {}, "Atividade no tempo"),
        el("div", { class: "suave pequeno" }, `${nomesEscala[dados.escala]}, em UTC. Clique em uma barra para ampliar.`,
          dados.sem_data ? ` ${formatoNumero(dados.sem_data)} registros sem data ficam fora do gráfico.` : "",
          dados.futuras ? ` ${formatoNumero(dados.futuras)} com data no futuro também, porque costumam ser carimbos inválidos.` : "")),
      el("div", { class: "grafico-acoes" }, voltar, botaoTabela)),
    area, dica, tabela));

  function desenhar() {
    const largura = Math.max(280, area.clientWidth);
    const margemE = 46;
    const alturaT = 110, alturaA = 46, vao = 26, eixo = 20;
    const n = dados.baldes.length;
    const passo = (largura - margemE) / n;
    const gap = n > 60 ? 1 : 2;
    const lb = Math.max(1, passo - gap);
    const maxT = Math.max(...dados.baldes.map((b) => b.total), 1);
    const maxA = Math.max(...dados.baldes.map((b) => b.alertas), 1);
    const yT = 16, yA = yT + alturaT + vao;
    const altura = yA + alturaA + eixo;
    const painel = [];

    const titulo = (texto, y) => svg("text", { x: margemE, y: y - 5, class: "g-titulo" }, texto);
    const grade = (y, a, max) => [
      svg("line", { x1: margemE, x2: largura, y1: y + a, y2: y + a, class: "g-base" }),
      svg("text", { x: margemE - 6, y: y + 9, class: "g-eixo", "text-anchor": "end" }, formatoNumero(max)),
      svg("text", { x: margemE - 6, y: y + a, class: "g-eixo", "text-anchor": "end" }, "0"),
    ];
    painel.push(titulo("Todos os registros", yT), ...grade(yT, alturaT, maxT));
    painel.push(titulo("Alertas", yA), ...grade(yA, alturaA, maxA));

    dados.baldes.forEach((b, i) => {
      const x = margemE + i * passo + gap / 2;
      const barra = (v, max, y, a) => {
        if (!v) return null;
        const h = Math.max(2, (v / max) * a);
        return svg("path", { d: caminhoBarra(x, y + a - h, lb, h), class: "g-barra" });
      };
      const mostrar = (ev) => {
        dica.replaceChildren(
          el("strong", {}, periodoLegivel(b.periodo)),
          el("div", {}, el("b", {}, formatoNumero(b.total)), " registros"),
          el("div", {}, el("b", {}, formatoNumero(b.alertas)), " alertas"));
        dica.classList.remove("oculto");
        const r = area.getBoundingClientRect();
        const px = ev.clientX ? ev.clientX - r.left : x;
        dica.style.left = `${Math.min(Math.max(0, px + 12), r.width - 170)}px`;
        dica.style.top = "24px";
      };
      const coluna = svg("g", {
        class: "g-coluna", tabindex: b.total ? "0" : null, role: b.total ? "button" : null,
        "aria-label": `${periodoLegivel(b.periodo)}: ${b.total} registros, ${b.alertas} alertas`,
        onpointermove: mostrar, onfocus: mostrar,
        onpointerleave: () => dica.classList.add("oculto"), onblur: () => dica.classList.add("oculto"),
        onclick: () => { if (b.total) aoEscolher(b.periodo); },
        onkeydown: (e) => { if (e.key === "Enter" && b.total) aoEscolher(b.periodo); },
      },
        // A area de clique e a coluna inteira, e nao so a parte pintada.
        svg("rect", { x: margemE + i * passo, y: yT, width: passo, height: altura - yT - eixo, class: "g-alvo" }),
        barra(b.total, maxT, yT, alturaT),
        barra(b.alertas, maxA, yA, alturaA));
      painel.push(coluna);
    });

    // Tres rotulos bastam: inicio, meio e fim, sem encavalar.
    const marcas = n <= 1 ? [0] : [0, Math.floor((n - 1) / 2), n - 1];
    [...new Set(marcas)].forEach((i, ordem, todas) => {
      const x = margemE + i * passo + passo / 2;
      const ancora = ordem === 0 && todas.length > 1 ? "start" : ordem === todas.length - 1 && todas.length > 1 ? "end" : "middle";
      painel.push(svg("text", { x: ancora === "start" ? margemE : ancora === "end" ? largura : x, y: altura - 4, class: "g-eixo", "text-anchor": ancora }, periodoLegivel(dados.baldes[i].periodo)));
    });
    area.replaceChildren(svg("svg", { width: largura, height: altura, role: "img", "aria-label": "Atividade no tempo" }, painel));
  }
  desenhar();
  new ResizeObserver(() => { if (area.isConnected && Math.abs(area.clientWidth - Number(area.querySelector("svg")?.getAttribute("width"))) > 8) desenhar(); }).observe(area);
}

const severidadesFiltro = [["critica", "Crítica"], ["alta", "Alta"], ["media", "Média"], ["baixa", "Baixa"], ["info", "Informativa"]];

async function desenharFiltros(alvo, base, filtro, escolha, comSeveridade, aoMudar) {
  const q = new URLSearchParams(filtro);
  q.delete("ordem");
  let fontes = [];
  try { fontes = await api(`${base}/fontes?${q}`); } catch { /* o filtro de fonte e so um atalho */ }
  const seletor = el("select", {
    "aria-label": "Filtrar por fonte",
    onchange: (e) => { escolha.fonte = e.target.value; aoMudar(); },
  }, el("option", { value: "" }, "Todas as fontes"),
    fontes.map((f) => {
      const o = el("option", { value: f.fonte }, `${f.fonte || "Sem fonte"} (${formatoNumero(f.total)})`);
      if (f.fonte === escolha.fonte) o.selected = true;
      return o;
    }));
  const botoes = comSeveridade && severidadesFiltro.map(([k, nome]) =>
    el("button", {
      class: `chip${escolha.severidade === k ? " ativo" : ""}`, "aria-pressed": String(escolha.severidade === k),
      onclick: () => { escolha.severidade = escolha.severidade === k ? "" : k; aoMudar(); },
    }, nome));
  const ativos = [
    escolha.de && `Período: ${periodoLegivel(escolha.de)}`,
    escolha.fonte && `Fonte: ${escolha.fonte}`,
    escolha.severidade && `Gravidade: ${nomesSeveridade[escolha.severidade]}`,
  ].filter(Boolean);
  const limpar = ativos.length > 0 && el("button", {
    class: "link suave pequeno",
    onclick: () => { escolha.de = escolha.ate = escolha.fonte = escolha.severidade = ""; aoMudar(); },
  }, "Limpar filtros");
  alvo.replaceChildren(el("div", { class: "filtros" }, seletor, botoes || null, limpar,
    ativos.length > 0 && el("span", { class: "suave pequeno" }, ativos.join(" · "))));
}

function painelMarcacao(base, l) {
  const nota = el("textarea", { rows: "3", placeholder: "Por que isto importa? (opcional)", "aria-label": "Nota do achado" });
  nota.value = l.nota || "";
  const situacao = el("span", { class: "suave pequeno" });
  let marcado = l.marcado;
  const principal = el("button", { class: "primario" });
  const retirar = el("button", {
    onclick: async () => {
      await enviarMarca(false);
      marcado = false;
      nota.value = "";
      atualizar("Marcação retirada.");
    },
  }, "Retirar marcação");
  const enviarMarca = (valor) => api(`${base}/registros/${l.id}/marca`, { method: "POST", body: JSON.stringify({ Marcado: valor, Nota: nota.value }) });
  function atualizar(texto) {
    principal.textContent = marcado ? "Salvar nota" : "Marcar achado";
    retirar.classList.toggle("oculto", !marcado);
    situacao.textContent = texto || (marcado ? "Marcado: entra no relatório." : "");
  }
  principal.addEventListener("click", async () => {
    try {
      await enviarMarca(true);
      marcado = true;
      atualizar("Guardado. Entra no relatório.");
    } catch (x) { situacao.textContent = x.message; }
  });
  atualizar();
  return el("div", { class: "marcacao" }, nota, el("div", { class: "marcacao-acoes" }, principal, retirar, situacao));
}

// Conteudo do arquivo, inclusive apagado, dentro da propria tela. Entra como texto, sem
// interpretar nada: o arquivo pode ser hostil.
function painelArquivo(base, l, casoId) {
  let d = {};
  try { d = typeof l.dados === "string" ? JSON.parse(l.dados) : (l.dados || {}); } catch { /* sem dados */ }
  if (!d.inode || d.particao === undefined || d.residual || d.modo?.startsWith("d/")) return null;
  const alvo = el("div", { class: "arquivo" });
  const botao = el("button", {
    onclick: async () => {
      botao.disabled = true;
      try {
        const a = await api(`${base}/registros/${l.id}/arquivo`);
        alvo.replaceChildren(
          el("div", { class: "suave pequeno" }, a.legivel
            ? `Mostrando ${formatoNumero(a.mostrado)} de ${formatoNumero(a.tamanho)} bytes.`
            : `Arquivo binário: início em hexadecimal. Tamanho: ${formatoNumero(a.tamanho)} bytes.`),
          el("pre", {}, a.legivel ? a.texto : a.hex));
      } catch (x) { alvo.replaceChildren(el("div", { class: "aviso erro" }, x.message)); }
      botao.disabled = false;
    },
  }, "Ver conteúdo");
  const copia = el("a", { href: `/casos/${encodeURIComponent(casoId)}/registros/${l.id}/copia` }, el("button", {}, "Salvar cópia"));
  return el("div", { class: "marcacao" }, el("div", { class: "marcacao-acoes" }, botao, copia), alvo);
}

// Busca dentro dos arquivos, no indice do exame profundo. Sem exame feito, nao mostra nada.
async function painelConteudo(alvo, base, q, abrirRegistro) {
  let r;
  try { r = await api(`${base}/conteudo?q=${encodeURIComponent(q)}`); } catch (x) {
    alvo.replaceChildren(el("div", { class: "aviso erro" }, x.message));
    return;
  }
  if (!r.total) return;
  const aviso = el("div", { class: "suave pequeno" });
  alvo.replaceChildren(el("div", { class: "painel conteudo" },
    el("h2", {}, `Citado dentro de ${formatoNumero(r.total)} ${r.total === 1 ? "arquivo" : "arquivos"}${r.total >= 100 ? " ou mais" : ""}`),
    aviso,
    el("div", { class: "lista-alertas" }, r.achados.map((a) =>
      el("button", {
        class: "link",
        onclick: async () => {
          try {
            const { id } = await api(`${base}/caminho?caminho=${encodeURIComponent(a.caminho)}`);
            abrirRegistro(id);
          } catch (x) { aviso.textContent = x.message; }
        },
      }, a.apagado === "true" && el("span", { class: "selo alta" }, "Apagado"), a.apagado === "true" ? " " : "", el("span", { class: "desc" }, a.caminho), " ", el("span", { class: "suave pequeno" }, a.categoria))))));
}

// Visao geral: so o que os registros mostram, sem conclusoes prontas. Tudo e clicavel.
async function abaVisao(area, base, acoes) {
  let v;
  try { v = await api(`${base}/visao`); } catch (x) {
    area.replaceChildren(el("div", { class: "aviso erro" }, x.message));
    return;
  }
  if (!v.resumo.registros) {
    area.replaceChildren(el("div", { class: "painel vazio" }, "Arraste uma evidência para começar. O resumo do caso aparece aqui."));
    return;
  }
  const dataCurta = (d) => (d ? d.slice(0, 10) : "");
  const frases = [];
  if (v.nucleo_inicio) {
    frases.push(`A maior parte da atividade registrada está entre ${dataCurta(v.nucleo_inicio)} e ${dataCurta(v.nucleo_fim)}, em UTC.`);
  }
  const quantidade = (tipo, um, varios) => {
    const n = (v.entidades[tipo] || []).length;
    return n ? `${n}${n === 6 ? " ou mais" : ""} ${n === 1 ? um : varios}` : null;
  };
  const achados = [quantidade("host", "máquina", "máquinas"), quantidade("usuario", "usuário", "usuários"), quantidade("ip", "IP", "IPs"), quantidade("dominio", "domínio", "domínios")].filter(Boolean);
  if (achados.length) frases.push(`Aparecem ${achados.join(", ")}.`);
  const totalAlertas = Object.values(v.resumo.alertas || {}).reduce((s, n) => s + n, 0);
  frases.push(totalAlertas
    ? `${formatoNumero(totalAlertas)} alertas automáticos pedem conferência na evidência de origem.`
    : "Nenhum alerta automático. Isso não indica que o caso está limpo: as detecções cobrem logs .evtx, executáveis e tráfego de rede, e logs .evt de sistemas antigos ainda não são lidos.");

  const avisos = [];
  if (v.falhas) avisos.push(`${v.falhas} ${v.falhas === 1 ? "leitura não terminou" : "leituras não terminaram"}.`);
  if (v.parciais) avisos.push(`${v.parciais} ${v.parciais === 1 ? "leitura foi parcial" : "leituras foram parciais"}.`);
  if (v.sem_resultado) avisos.push(`${v.sem_resultado} ${v.sem_resultado === 1 ? "leitura não trouxe resultado" : "leituras não trouxeram resultado"}.`);

  const grafico = el("div");
  const ordemBlocos = ["host", "usuario", "ip", "dominio", "email", "regra"].filter((t) => v.entidades[t]);
  const blocosEntidades = ordemBlocos.map((tipo) => [tipo, v.entidades[tipo]]).map(([tipo, lista]) =>
    el("div", {},
      el("h3", {}, nomesEntidadePlural[tipo] || tipo),
      el("div", { class: "etiquetas" }, lista.map((e) =>
        el("button", { onclick: () => acoes.abrirEntidade(e) }, `${e.valor} (${formatoNumero(e.registros)})`)))));

  const profundo = el("div");
  api(`${base}/aprofundar`).then((p) => {
    if (!p.aplicavel) return;
    const situacao = el("div", { class: "suave pequeno" });
    profundo.replaceChildren(el("div", { class: "painel exame" },
      el("div", {},
        el("h2", {}, "Exame profundo"),
        el("div", { class: "suave pequeno" }, p.pronto
          ? "Feito. A busca do topo agora também procura dentro de documentos, e-mails e mensagens."
          : "Lê o conteúdo de documentos, e-mails e mensagens, recupera arquivos e monta a linha do tempo completa. Pode levar bastante tempo e ocupar vários GB."),
        situacao),
      !p.pronto && el("button", {
          onclick: async (e) => {
            e.target.disabled = true;
            e.target.textContent = "Em andamento";
            await api(`${base}/processar?profundo=1`, { method: "POST" });
            window.acompanharCaso?.();
          },
        }, "Iniciar exame profundo")));
  }).catch(() => {});

  area.replaceChildren(
    profundo,
    el("div", { class: "painel resumo" },
      el("h2", {}, "Resumo do caso"),
      frases.map((f) => el("p", {}, f)),
      avisos.length > 0 && el("button", { class: "link aviso-linha", onclick: () => acoes.abrirAba("evidencias") }, avisos.join(" "), " Ver leituras"),
      v.marcados > 0 && el("button", { class: "link suave pequeno", onclick: () => acoes.abrirAba("marcados") }, `${v.marcados} ${v.marcados === 1 ? "achado marcado" : "achados marcados"}`)),
    grafico,
    el("div", { class: "grade" },
      el("div", { class: "painel" },
        el("h2", {}, "Principais alertas"),
        v.alertas.length ? el("div", { class: "lista-alertas" }, v.alertas.map((a) =>
          el("button", { class: "link", onclick: () => acoes.buscar(a.descricao) },
            selo(a.severidade), " ", el("span", {}, a.descricao), " ", el("span", { class: "suave pequeno" }, `${formatoNumero(a.total)}×`)))) :
          el("div", { class: "suave" }, "Nenhum.")),
      el("div", { class: "painel" },
        el("h2", {}, "Quem e o quê aparece mais"),
        blocosEntidades.length ? el("div", { class: "blocos" }, blocosEntidades) : el("div", { class: "suave" }, "Nada identificado."))));
  desenharGrafico(grafico, base, {}, (periodo) => acoes.abrirPeriodo(periodo));
}

const nomesEntidadePlural = { host: "Máquinas", usuario: "Usuários", ip: "IPs", dominio: "Domínios", email: "E-mails", regra: "Regras disparadas" };

// Mapa de conexoes: os grupos ficam em setores do circulo, entao o tipo de cada ponto se
// le pela posicao e pelo rotulo, e nao por uma cor.
async function abaConexoes(area, base, abrir) {
  let m;
  try { m = await api(`${base}/conexoes`); } catch (x) {
    area.replaceChildren(el("div", { class: "aviso erro" }, x.message));
    return;
  }
  if (!m.nos.length) {
    area.replaceChildren(el("div", { class: "painel vazio" }, "Nenhuma conexão ainda. Ela aparece quando dois itens, como dois IPs ou uma máquina e um usuário, surgem no mesmo registro."));
    return;
  }
  const alvo = el("div", { class: "mapa-area" });
  const dica = el("div", { class: "suave pequeno mapa-dica" }, "Passe o mouse para ver as ligações. Clique para abrir os registros.");
  const lista = el("div", { class: "tabela oculto" }, el("table", {},
    el("thead", {}, el("tr", {}, el("th", {}, "De"), el("th", {}, "Para"), el("th", {}, "Registros em comum"))),
    el("tbody", {}, [...m.ligacoes].sort((a, b) => b.total - a.total).map((l) => {
      const nome = (id) => m.nos.find((n) => n.id === id)?.valor;
      return el("tr", {}, el("td", { class: "desc" }, nome(l.a)), el("td", { class: "desc" }, nome(l.b)), el("td", {}, formatoNumero(l.total)));
    }))));
  const botao = el("button", { onclick: () => { botao.textContent = lista.classList.toggle("oculto") ? "Ver como tabela" : "Ocultar tabela"; } }, "Ver como tabela");
  area.replaceChildren(el("div", { class: "painel" },
    el("div", { class: "grafico-topo" },
      el("div", {}, el("h2", {}, "Mapa de conexões"),
        el("div", { class: "suave pequeno" }, "Itens ligados aparecem juntos nos mesmos registros. Isso não prova que um agiu sobre o outro.")),
      el("div", { class: "grafico-acoes" }, botao)),
    dica, alvo, lista));

  const largura = Math.max(320, Math.min(alvo.clientWidth, 1000));
  const altura = Math.min(620, Math.max(420, largura * 0.62));
  const cx = largura / 2, cy = altura / 2;
  const raio = Math.min(cx, cy) - (largura < 560 ? 44 : 70);
  const grupos = {};
  m.nos.forEach((n) => (grupos[n.tipo] = grupos[n.tipo] || []).push(n));
  const pos = {};
  const titulos = [];
  const total = m.nos.length;
  const folga = Object.keys(grupos).length > 1 ? 1.5 : 0;
  const unidades = total + folga * Object.keys(grupos).length;
  let cursor = -Math.PI / 2;
  Object.entries(grupos).forEach(([tipo, nos]) => {
    const inicio = cursor;
    nos.forEach((n, i) => {
      const a = cursor + (i + 0.5) * ((2 * Math.PI) / unidades);
      pos[n.id] = { x: cx + raio * Math.cos(a), y: cy + raio * Math.sin(a), a };
    });
    cursor += nos.length * ((2 * Math.PI) / unidades);
    const meio = (inicio + cursor) / 2;
    titulos.push({ tipo, x: cx + (raio * 0.5) * Math.cos(meio), y: cy + (raio * 0.5) * Math.sin(meio) });
    cursor += folga * ((2 * Math.PI) / unidades);
  });
  const maxL = Math.max(...m.ligacoes.map((l) => l.total), 1);
  const maxN = Math.max(...m.nos.map((n) => n.registros), 1);
  const linhas = m.ligacoes.map((l) => svg("path", {
    d: `M${pos[l.a].x},${pos[l.a].y}Q${cx},${cy} ${pos[l.b].x},${pos[l.b].y}`,
    class: "m-linha", "stroke-width": 1 + 2.5 * Math.sqrt(l.total / maxL), "data-a": l.a, "data-b": l.b,
  }));
  const destacar = (id) => {
    const vizinhos = new Set([id]);
    linhas.forEach((c) => {
      const a = Number(c.dataset.a), b = Number(c.dataset.b);
      const ligada = id != null && (a === id || b === id);
      c.classList.toggle("ativa", ligada);
      c.classList.toggle("apagada", id != null && !ligada);
      if (ligada) { vizinhos.add(a); vizinhos.add(b); }
    });
    grupoNos.querySelectorAll(".m-no").forEach((g) => g.classList.toggle("apagada", id != null && !vizinhos.has(Number(g.dataset.id))));
  };
  const grupoNos = svg("g", {}, m.nos.map((n) => {
    const p = pos[n.id];
    const r = 5 + 8 * Math.sqrt(n.registros / maxN);
    const direita = Math.cos(p.a) >= 0;
    const texto = n.valor.length > 24 ? `${n.valor.slice(0, 23)}…` : n.valor;
    return svg("g", {
      class: "m-no", tabindex: "0", role: "button", "data-id": n.id,
      "aria-label": `${nomesEntidade[n.tipo] || n.tipo}: ${n.valor}`,
      onpointerenter: () => destacar(n.id), onpointerleave: () => destacar(null),
      onfocus: () => destacar(n.id), onblur: () => destacar(null),
      onclick: () => abrir(n),
      onkeydown: (e) => { if (e.key === "Enter") abrir(n); },
    },
      svg("title", {}, `${nomesEntidade[n.tipo] || n.tipo}: ${n.valor}`),
      svg("circle", { cx: p.x, cy: p.y, r: 14, class: "m-alvo" }),
      svg("circle", { cx: p.x, cy: p.y, r, class: "m-ponto" }),
      // Perto do topo e da base, os pontos ficam lado a lado: o rotulo sobe ou desce para fora.
      largura >= 560 && svg("text", { x: p.x + (direita ? r + 5 : -r - 5), y: p.y + 4 + 12 * Math.sin(p.a), class: "m-rotulo", "text-anchor": direita ? "start" : "end" }, texto));
  }));
  alvo.replaceChildren(svg("svg", { width: largura, height: altura, role: "img", "aria-label": "Mapa de conexões" },
    linhas,
    titulos.map((t) => svg("text", { x: t.x, y: t.y, class: "m-grupo", "text-anchor": "middle" }, nomesEntidadePlural[t.tipo] || t.tipo)),
    grupoNos));
}
