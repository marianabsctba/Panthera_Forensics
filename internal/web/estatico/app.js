"use strict";
// Tudo o que vem do caso e tratado como dado hostil: a tela e montada so com
// textContent, nunca com innerHTML.

const token = document.querySelector('meta[name="token"]').content;
const app = document.getElementById("app");

function el(tag, props, ...filhos) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v === true) n.setAttribute(k, "");
    else if (v !== false && v != null) n.setAttribute(k, v);
  }
  for (const f of filhos.flat()) {
    if (f == null || f === false) continue;
    n.append(f instanceof Node ? f : document.createTextNode(String(f)));
  }
  return n;
}

async function api(rota, opcoes = {}) {
  const r = await fetch(rota, {
    ...opcoes,
    headers: { ...(opcoes.headers || {}), ...(opcoes.method && opcoes.method !== "GET" ? { "X-Token": token } : {}) },
  });
  const dados = await r.json().catch(() => null);
  if (!r.ok) throw new Error((dados && dados.erro) || "Algo deu errado. Tente de novo.");
  return dados;
}

const nomesSeveridade = { critica: "Crítica", alta: "Alta", media: "Média", baixa: "Baixa", info: "Informativa" };
const nomesEntidade = { host: "Máquina", usuario: "Usuário", arquivo: "Arquivo", ip: "IP", hash: "Hash", url: "Endereço" };

function dataHora(l) {
  if (l.quando) return textoData(l.quando);
  return l.quando_bruto ? `Data ilegível: ${l.quando_bruto}` : "Sem data";
}

function tamanho(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toLocaleString("pt-BR", { maximumFractionDigits: 1 })} ${u[i]}`;
}

function selo(sev) {
  return sev ? el("span", { class: `selo ${sev}` }, nomesSeveridade[sev] || sev) : null;
}

let pararEstado = null;

function cabecalho(aoBuscar) {
  return el("header", {},
    el("button", { class: "link marca", onclick: telaInicial }, el("img", { src: "/simbolo.png", alt: "" }), "Panthera Forensics"),
    el("button", {
      class: "encerrar",
      onclick: async (e) => {
        try {
          await api("/api/encerrar", { method: "POST" });
          document.body.replaceChildren(el("main", {}, el("h1", {}, "Panthera Forensics encerrado"), el("p", { class: "suave" }, "Pode fechar esta aba.")));
        } catch (x) { e.target.textContent = x.message; }
      },
    }, "Encerrar"),
    aoBuscar && el("input", {
      class: "busca", type: "search", "aria-label": "Buscar no caso",
      placeholder: "Buscar nome, hash, IP, usuário…",
      onkeydown: (e) => { if (e.key === "Enter") aoBuscar(e.target.value.trim()); },
    }));
}

// Tela inicial -------------------------------------------------------------

async function telaInicial() {
  if (pararEstado) pararEstado();
  const erro = el("div");
  const form = el("form", {
    class: "painel",
    onsubmit: async (e) => {
      e.preventDefault();
      const d = new FormData(form);
      try {
        const c = await api("/api/casos", {
          method: "POST",
          body: JSON.stringify({ Nome: d.get("nome"), Numero: d.get("numero"), Perito: d.get("perito") }),
        });
        telaCaso(c.id);
      } catch (x) { erro.replaceChildren(el("div", { class: "aviso erro" }, x.message)); }
    },
  },
    el("h2", {}, "Novo caso"),
    el("label", {}, "Nome", el("input", { name: "nome", required: true, placeholder: "Notebook apreendido" })),
    el("label", {}, "Número do processo (opcional)", el("input", { name: "numero" })),
    el("label", {}, "Responsável (opcional)", el("input", { name: "perito" })),
    erro,
    el("button", { class: "primario", type: "submit" }, "Criar caso"));

  const lista = el("div", { class: "lista-casos" });
  const preparo = el("div");
  app.replaceChildren(cabecalho(), el("main", {},
    el("div", { class: "capa" },
      el("img", { src: "/simbolo.png", alt: "Símbolo da Panthera" }),
      el("div", {}, el("h1", {}, "Panthera Forensics"), el("div", { class: "suave" }, "Abra um caso, arraste a evidência e investigue."))),
    preparo,
    el("div", { class: "grade" }, form, el("div", { class: "painel" }, el("h2", {}, "Casos"), lista))));
  avisoPreparo(preparo);

  try {
    const casos = await api("/api/casos");
    if (!casos.length) lista.append(el("div", { class: "vazio" }, "Nenhum caso ainda."));
    for (const c of casos) {
      lista.append(el("button", { onclick: () => telaCaso(c.id) },
        el("strong", {}, c.nome),
        el("div", { class: "suave pequeno" }, [c.numero, c.criado_em.slice(0, 10)].filter(Boolean).join(" · "))));
    }
  } catch (x) { lista.replaceChildren(el("div", { class: "aviso erro" }, x.message)); }
}

async function avisoPreparo(alvo) {
  let m;
  try { m = await api("/api/modulos"); } catch { return; }
  if (m.instalando) {
    alvo.replaceChildren(el("div", { class: "aviso" }, "Preparando as ferramentas de análise. Isso só acontece uma vez."));
    setTimeout(() => { if (alvo.isConnected) avisoPreparo(alvo); }, 2000);
    return;
  }
  if (m.erro) {
    alvo.replaceChildren(el("div", { class: "aviso erro" }, "Parte da preparação falhou: ", m.erro, " ",
      el("button", { onclick: () => instalar(alvo) }, "Tentar de novo")));
    return;
  }
  if (m.pendentes > 0) {
    alvo.replaceChildren(el("div", { class: "aviso" },
      `Falta preparar ${m.pendentes} ${m.pendentes === 1 ? "leitura" : "leituras"} de evidência. `,
      el("button", { class: "primario", onclick: () => instalar(alvo) }, "Preparar agora")));
    return;
  }
  alvo.replaceChildren();
}

async function instalar(alvo) {
  await api("/api/modulos/instalar", { method: "POST" });
  avisoPreparo(alvo);
}

// Caso ---------------------------------------------------------------------

async function telaCaso(id) {
  if (pararEstado) pararEstado();
  const base = `/api/casos/${encodeURIComponent(id)}`;
  const area = el("div");
  const numeros = el("div", { class: "numeros" });
  const estado = el("div");
  const abas = el("nav", { class: "abas" });
  let abaAtual = "visao";

  const definicoes = [
    ["visao", "Visão geral", () => abaVisao(area, base, { abrirAba, abrirEntidade, buscar, abrirPeriodo })],
    ["atencao", "O que merece atenção", () => abaRegistros(area, base, { tipo: "alerta", ordem: "gravidade" }, "Nenhum achado automático. Isso não indica que o caso está limpo: as detecções cobrem logs .evtx, executáveis e tráfego de rede, e logs .evt de sistemas antigos ainda não são lidos.", true)],
    ["timeline", "Linha do tempo", () => abaRegistros(area, base, {}, "A linha do tempo aparece depois que uma evidência é lida.")],
    ["acessos", "Acessos", () => abaAcessos(area, base, buscar)],
    ["conexoes", "Conexões", () => abaConexoes(area, base, abrirEntidade)],
    ["entidades", "Pessoas e objetos", () => abaEntidades(area, base, abrirEntidade)],
    ["marcados", "Marcados", () => abaRegistros(area, base, { marcados: "1" }, "Nada marcado ainda. Abra um registro e use “Marcar achado”: ele entra no relatório, com a sua nota.")],
    ["evidencias", "Evidências", () => abaEvidencias(area, base)],
  ];

  function abrirAba(chave) {
    abaAtual = chave;
    abas.replaceChildren(...definicoes.map(([k, nome]) =>
      el("button", { class: k === chave ? "ativa" : "", onclick: () => abrirAba(k) }, nome)));
    definicoes.find(([k]) => k === chave)[2]();
  }
  function abrirPeriodo(periodo) {
    abaAtual = "timeline";
    abas.replaceChildren(...definicoes.map(([k, nome]) =>
      el("button", { class: k === "timeline" ? "ativa" : "", onclick: () => abrirAba(k) }, nome)));
    abaRegistros(area, base, {}, "Nada encontrado nesse período.", false, null, periodo);
  }
  function abrirEntidade(e) {
    abas.replaceChildren(...definicoes.map(([k, nome]) => el("button", { onclick: () => abrirAba(k) }, nome)));
    abaRegistros(area, base, { entidade: e.id }, "Nada encontrado.", false, `${nomesEntidade[e.tipo] || e.tipo}: ${e.valor}`);
  }
  function buscar(q) {
    if (!q) return abrirAba(abaAtual);
    abas.replaceChildren(...definicoes.map(([k, nome]) => el("button", { onclick: () => abrirAba(k) }, nome)));
    abaRegistros(area, base, { q }, "Nada encontrado para essa busca.", false, `Busca: ${q}`);
    const noConteudo = el("div");
    area.prepend(noConteudo);
    painelConteudo(noConteudo, base, q, (registro) => abrirDetalhe(base, registro, id));
  }
  window.abrirEntidadeCaso = abrirEntidade;

  const entradaArquivos = el("input", { type: "file", multiple: true, class: "oculto", onchange: (e) => enviar([...e.target.files]) });
  const entradaPasta = el("input", { type: "file", webkitdirectory: true, class: "oculto", onchange: (e) => enviar([...e.target.files]) });
  const soltar = el("div", {
    class: "soltar",
    ondragover: (e) => { e.preventDefault(); soltar.classList.add("ativo"); },
    ondragleave: () => soltar.classList.remove("ativo"),
    ondrop: async (e) => {
      e.preventDefault();
      soltar.classList.remove("ativo");
      enviar(await arquivosSoltos(e.dataTransfer));
    },
  },
    el("strong", {}, "Arraste a evidência para cá"),
    el("div", { class: "suave pequeno detalhe-soltar" }, "Arquivo, pasta ou pacote de coleta. O conteúdo é identificado e lido automaticamente."),
    el("div", { class: "acoes" },
      el("button", { onclick: () => entradaArquivos.click() }, "Escolher arquivos"),
      el("button", { onclick: () => entradaPasta.click() }, "Escolher pasta")),
    entradaArquivos, entradaPasta);

  async function enviar(arquivos) {
    if (!arquivos.length) return;
    const total = arquivos.reduce((s, f) => s + f.size, 0);
    let enviados = 0;
    const falhas = [];
    for (const f of arquivos) {
      mostrarProgresso(estado, /\.zip$/i.test(f.name)
        ? `Preservando e abrindo ${f.name}. Pacotes grandes levam alguns minutos.`
        : `Preservando ${f.name}`, enviados, total || 1);
      const origem = f.webkitRelativePath || f.caminhoRelativo || f.name;
      try {
        await api(`${base}/evidencias?nome=${encodeURIComponent(f.name)}&origem=${encodeURIComponent(origem)}`, { method: "POST", body: f });
      } catch (x) { falhas.push(x.message); }
      enviados += f.size;
    }
    if (falhas.length) estado.replaceChildren(el("div", { class: "aviso erro" }, falhas.join(" ")));
    await api(`${base}/processar`, { method: "POST" });
    acompanhar();
  }

  async function atualizarNumeros() {
    const { caso, resumo } = await api(`${base}/resumo`);
    titulo.textContent = caso.nome;
    subtitulo.textContent = [caso.numero, caso.perito].filter(Boolean).join(" · ");
    // Com evidencia no caso, o campo de arrastar so precisa continuar disponivel.
    soltar.classList.toggle("compacto", resumo.evidencias > 0);
    localFuso.replaceChildren(seletorFuso(resumo.fuso, () => abrirAba(abaAtual)));
    const a = resumo.alertas || {};
    numeros.replaceChildren(
      numero(a.critica || 0, "Críticos"), numero(a.alta || 0, "Altos"),
      numero(resumo.registros, "Registros"), numero(resumo.entidades, "Pessoas e objetos"),
      numero(resumo.evidencias, "Evidências"));
  }

  window.acompanharCaso = () => { tinhaRodando = true; acompanhar(); };
  let vivo = true;
  pararEstado = () => { vivo = false; pararEstado = null; };
  let tinhaRodando = false;
  async function acompanhar() {
    if (!vivo) return;
    let e;
    try { e = await api(`${base}/estado`); } catch { return; }
    if (e.rodando) {
      tinhaRodando = true;
      mostrarProgresso(estado, e.etapa ? `Lendo: ${e.etapa}` : "Identificando as evidências", e.feitas, e.total || 1);
      setTimeout(acompanhar, 1000);
      return;
    }
    if (tinhaRodando || e.resultado) {
      estado.replaceChildren(...avisosResultado(e));
      await atualizarNumeros();
      if (tinhaRodando) abrirAba(abaAtual);
      tinhaRodando = false;
    }
  }

  const titulo = el("h1");
  const subtitulo = el("div", { class: "suave" });
  const verificacao = el("span", { class: "pequeno" });
  const localFuso = el("span");
  app.replaceChildren(cabecalho(buscar), el("main", {},
    el("div", { class: "topo-caso" },
      el("div", {}, titulo, subtitulo),
      el("div", {},
        localFuso, " ", verificacao, " ",
        el("button", {
          onclick: async () => {
            verificacao.textContent = "Conferindo…";
            const conf = await api(`${base}/verificar`, { method: "POST" });
            const ruins = conf.filter((c) => !c.integra);
            verificacao.replaceChildren(ruins.length
              ? el("span", { class: "selo critica" }, `${ruins.length} com problema`)
              : el("span", { class: "selo ok" }, "Evidências íntegras"));
          },
        }, "Conferir integridade"), " ",
        el("a", { href: `/casos/${encodeURIComponent(id)}/relatorio`, target: "_blank", rel: "noopener" },
          el("button", { class: "primario" }, "Gerar relatório")))),
    soltar, estado, numeros, abas, area));

  try {
    await atualizarNumeros();
    abrirAba("visao");
    acompanhar();
  } catch (x) {
    area.replaceChildren(el("div", { class: "aviso erro" }, x.message));
  }
}

function numero(valor, rotulo) {
  return el("div", { class: "numero" }, el("b", {}, Number(valor).toLocaleString("pt-BR")), el("span", {}, rotulo));
}

function mostrarProgresso(alvo, texto, feitas, total) {
  const pct = Math.min(100, Math.round((feitas / total) * 100));
  const barra = el("div");
  barra.style.width = `${pct}%`;
  alvo.replaceChildren(el("div", { class: "aviso" }, texto, el("div", { class: "progresso" }, barra)));
}

function avisosResultado(e) {
  const r = e.resultado || {};
  const avisos = [];
  if (e.erro) avisos.push(el("div", { class: "aviso erro" }, "O processamento parou: ", e.erro));
  for (const f of r.falhas || []) avisos.push(el("div", { class: "aviso erro" }, "Não consegui concluir esta leitura. ", f));
  if ((r.ausentes || []).length) {
    avisos.push(el("div", { class: "aviso" }, "Ainda não preparado, por isso não foi lido: ", r.ausentes.join(", "), ". Prepare na tela inicial e envie de novo."));
  }
  if (r.sem_modulo) {
    avisos.push(el("div", { class: "aviso" }, `${r.sem_modulo.toLocaleString("pt-BR")} ${r.sem_modulo === 1 ? "arquivo está em formato" : "arquivos estão em formatos"} sem leitura própria. Foram preservados e listados na linha do tempo, e o texto legível entra na busca.`));
  }
  return avisos;
}

async function arquivosSoltos(dt) {
  const itens = [...dt.items].map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if (!itens.length) return [...dt.files];
  const saida = [];
  async function visitar(entrada, prefixo) {
    if (entrada.isFile) {
      const f = await new Promise((ok, erro) => entrada.file(ok, erro));
      f.caminhoRelativo = prefixo + entrada.name;
      saida.push(f);
      return;
    }
    const leitor = entrada.createReader();
    for (;;) {
      const lote = await new Promise((ok, erro) => leitor.readEntries(ok, erro));
      if (!lote.length) break;
      for (const filho of lote) await visitar(filho, `${prefixo}${entrada.name}/`);
    }
  }
  for (const i of itens) await visitar(i, "");
  return saida;
}

// Abas ---------------------------------------------------------------------

async function abaRegistros(area, base, filtroBase, textoVazio, comGravidade, titulo, periodoInicial) {
  // O filtro escolhido na tela soma ao filtro fixo da aba.
  const escolha = { de: periodoInicial || "", ate: periodoInicial || "", fonte: "", severidade: "" };
  const grafico = el("div");
  const filtros = el("div");
  const corpo = el("tbody");
  const mais = el("div", { class: "mais" });
  const vazio = el("div", { class: "painel vazio oculto" }, textoVazio);
  const tabela = el("div", { class: "tabela painel" },
    el("table", {},
      el("thead", {}, el("tr", {},
        comGravidade && el("th", {}, "Gravidade"),
        el("th", {}, rotuloQuando()), el("th", {}, "O que aconteceu"), el("th", {}, "Fonte"))),
      corpo), mais);
  area.replaceChildren(titulo ? el("h2", {}, titulo) : "", grafico, filtros, vazio, tabela);
  const limite = 200;
  let deslocar = 0;
  let geracao = 0;
  const filtroAtual = () => {
    const f = { ...filtroBase };
    for (const [k, v] of Object.entries(escolha)) if (v) f[k] = v;
    return f;
  };
  function aplicar() {
    deslocar = 0;
    geracao++;
    corpo.replaceChildren();
    mais.replaceChildren();
    desenharGrafico(grafico, base, filtroAtual(), (periodo) => {
      if (periodo) { escolha.de = periodo; escolha.ate = periodo; } else { escolha.de = ""; escolha.ate = ""; }
      aplicar();
    });
    desenharFiltros(filtros, base, filtroAtual(), escolha, !filtroBase.severidade, aplicar);
    carregar();
  }
  async function carregar() {
    const minha = geracao;
    const q = new URLSearchParams({ ...filtroAtual(), limite, deslocar });
    let linhas;
    try { linhas = await api(`${base}/registros?${q}`); } catch (x) {
      area.replaceChildren(el("div", { class: "aviso erro" }, x.message));
      return;
    }
    if (minha !== geracao) return;
    const semNada = !linhas.length && deslocar === 0;
    vazio.classList.toggle("oculto", !semNada);
    tabela.classList.toggle("oculto", semNada);
    if (semNada) return;
    for (const l of linhas) {
      corpo.append(el("tr", { class: "clicavel", tabindex: "0", onclick: () => abrirDetalhe(base, l.id), onkeydown: (e) => { if (e.key === "Enter") abrirDetalhe(base, l.id); } },
        comGravidade && el("td", {}, selo(l.severidade)),
        el("td", { class: "data" }, dataHora(l)),
        el("td", { class: "desc" }, selo(comGravidade ? "" : l.severidade), comGravidade || !l.severidade ? "" : " ", l.descricao),
        el("td", { class: "suave pequeno" }, l.fonte)));
    }
    deslocar += linhas.length;
    mais.replaceChildren(linhas.length === limite ? el("button", { onclick: carregar }, "Mostrar mais") : "");
  }
  aplicar();
}

async function abrirDetalhe(base, id) {
  const casoId = decodeURIComponent(base.split("/").pop());
  document.querySelector(".gaveta")?.remove();
  const l = await api(`${base}/registros/${id}`);
  const fechar = () => { gaveta.remove(); document.removeEventListener("keydown", esc); };
  const esc = (e) => { if (e.key === "Escape") fechar(); };
  document.addEventListener("keydown", esc);
  let dados = "";
  try { dados = JSON.stringify(l.dados, null, 2); } catch { dados = String(l.dados); }
  const gaveta = el("aside", { class: "gaveta", role: "dialog", "aria-label": "Detalhe do registro" },
    el("button", { style: null, onclick: fechar }, "Fechar"),
    el("h2", { class: "titulo-detalhe" }, " "),
    el("div", {}, selo(l.severidade)),
    el("dl", {},
      el("dt", {}, rotuloQuando()), el("dd", {}, dataHora(l)),
      fusoEscolhido.zona && l.quando && el("dt", {}, "Em UTC"),
      fusoEscolhido.zona && l.quando && el("dd", {}, l.quando.slice(0, 19).replace("T", " ")),
      el("dt", {}, "Fonte"), el("dd", {}, l.fonte || "Não informada"),
      el("dt", {}, "Leitura"), el("dd", {}, l.modulo),
      el("dt", {}, "Origem"), el("dd", {}, el("code", {}, [l.origem_arquivo, l.origem_local && `#${l.origem_local}`].filter(Boolean).join(" ") || "Não informada"))),
    (l.entidades || []).length > 0 && el("div", {},
      el("h2", {}, "Ligado a"),
      el("div", { class: "etiquetas" }, l.entidades.map((e) =>
        el("button", { onclick: () => { fechar(); window.abrirEntidadeCaso(e); } },
          `${nomesEntidade[e.tipo] || e.tipo}: ${e.valor} (${e.registros})`)))),
    painelArquivo(base, l, casoId),
    painelMarcacao(base, l),
    el("h2", { class: "pequeno" }, "Dados originais"),
    el("pre", {}, dados));
  gaveta.querySelector(".titulo-detalhe").textContent = l.descricao;
  document.body.append(gaveta);
}

async function abaEntidades(area, base, abrir) {
  let lista;
  try { lista = await api(`${base}/entidades`); } catch (x) {
    area.replaceChildren(el("div", { class: "aviso erro" }, x.message));
    return;
  }
  if (!lista.length) {
    area.replaceChildren(el("div", { class: "painel vazio" }, "Usuários, máquinas e arquivos aparecem aqui depois que uma evidência é lida."));
    return;
  }
  area.replaceChildren(el("div", { class: "tabela painel" }, el("table", {},
    el("thead", {}, el("tr", {}, el("th", {}, "Tipo"), el("th", {}, "Valor"), el("th", {}, "Registros"))),
    el("tbody", {}, lista.map((e) => el("tr", { class: "clicavel", tabindex: "0", onclick: () => abrir(e), onkeydown: (x) => { if (x.key === "Enter") abrir(e); } },
      el("td", { class: "suave" }, nomesEntidade[e.tipo] || e.tipo),
      el("td", { class: "desc" }, e.valor),
      el("td", {}, e.registros)))))));
}

async function abaEvidencias(area, base) {
  let d;
  try { d = await api(`${base}/evidencias`); } catch (x) {
    area.replaceChildren(el("div", { class: "aviso erro" }, x.message));
    return;
  }
  if (!d.evidencias.length) {
    area.replaceChildren(el("div", { class: "painel vazio" }, "Nenhuma evidência ainda."));
    return;
  }
  area.replaceChildren(
    el("div", { class: "tabela painel" }, el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Nome"), el("th", {}, "Tamanho"), el("th", {}, "SHA-256"))),
      el("tbody", {}, d.evidencias.map((e) => el("tr", {},
        el("td", { class: "desc" }, e.nome, el("div", { class: "suave pequeno" }, e.origem)),
        el("td", { class: "data" }, tamanho(e.tamanho)),
        el("td", {}, el("code", {}, e.sha256))))))),
    el("div", { class: "grafico-topo titulo-leituras" },
      el("h2", {}, "Leituras"),
      el("button", {
        onclick: async (e) => {
          e.target.disabled = true;
          e.target.textContent = "Lendo. Acompanhe no topo.";
          await api(`${base}/processar?refazer=1`, { method: "POST" });
          window.acompanharCaso?.();
        },
      }, "Ler de novo")),
    d.execucoes.length ? el("div", { class: "tabela painel" }, el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Leitura"), el("th", {}, "Situação"), el("th", {}, "Registros"))),
      el("tbody", {}, d.execucoes.map((x) => el("tr", {},
        el("td", {}, x.titulo),
        el("td", {}, x.estado === "concluida" && x.erro ? el("span", { class: "selo falhou" }, "Parcial: confira esta leitura")
          : x.estado === "concluida" && x.registros === 0 ? el("span", { class: "selo falhou" }, "Sem resultado: confira esta leitura")
          : x.estado === "concluida" ? el("span", { class: "selo ok" }, "Concluída")
          : x.estado === "falhou" ? el("span", { class: "selo falhou" }, "Não concluída") : "Em andamento",
          x.erro && el("div", { class: "suave pequeno desc" }, x.erro)),
        el("td", {}, x.registros)))))) : "");
}

telaInicial();
