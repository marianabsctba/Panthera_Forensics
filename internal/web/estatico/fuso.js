"use strict";
// Mostrar as datas em outro fuso. O banco continua sempre em UTC: isto so muda a tela. Com
// um fuso com regras, e nao uma diferenca fixa, o horario de verao de cada data sai certo.

// Nome gravado pelo Windows no Registro -> fuso com historico de regras.
const fusosWindows = {
  "Central Standard Time": "America/Chicago",
  "Eastern Standard Time": "America/New_York",
  "Pacific Standard Time": "America/Los_Angeles",
  "Mountain Standard Time": "America/Denver",
  "E. South America Standard Time": "America/Sao_Paulo",
  "SA Eastern Standard Time": "America/Fortaleza",
  "Central Brazilian Standard Time": "America/Cuiaba",
  "SA Western Standard Time": "America/Manaus",
  "Tocantins Standard Time": "America/Araguaina",
  "Bahia Standard Time": "America/Bahia",
  "GMT Standard Time": "Europe/London",
  "W. Europe Standard Time": "Europe/Berlin",
  "Romance Standard Time": "Europe/Paris",
  "Central Europe Standard Time": "Europe/Budapest",
  "Tokyo Standard Time": "Asia/Tokyo",
  "China Standard Time": "Asia/Shanghai",
  "India Standard Time": "Asia/Kolkata",
  "UTC": "UTC",
  "Coordinated Universal Time": "UTC",
};

const fusoEscolhido = { zona: "", rotulo: "UTC" };

function converterData(iso, zona) {
  const data = new Date(`${iso.slice(0, 23)}Z`);
  const partes = new Intl.DateTimeFormat("sv-SE", {
    timeZone: zona, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  }).format(data);
  return partes;
}

function textoData(iso) {
  if (!fusoEscolhido.zona) return iso.slice(0, 19).replace("T", " ");
  return converterData(iso, fusoEscolhido.zona);
}

function rotuloQuando() {
  return `Quando (${fusoEscolhido.rotulo})`;
}

// Monta o seletor. O fuso da evidencia so aparece se foi lido dela e e conhecido.
function seletorFuso(fusoEvidencia, aoMudar) {
  const zonaEvidencia = fusosWindows[fusoEvidencia];
  const meu = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const opcoes = [["", "UTC", "UTC"]];
  if (zonaEvidencia) opcoes.push([zonaEvidencia, `Da máquina analisada (${zonaEvidencia})`, "máquina analisada"]);
  opcoes.push(["America/Sao_Paulo", "Brasília", "Brasília"]);
  if (meu && meu !== "America/Sao_Paulo") opcoes.push([meu, `Meu fuso (${meu})`, "meu fuso"]);
  const s = el("select", {
    "aria-label": "Fuso das datas",
    onchange: (e) => {
      const o = opcoes[e.target.selectedIndex];
      fusoEscolhido.zona = o[0];
      fusoEscolhido.rotulo = o[2];
      aoMudar();
    },
  }, opcoes.map((o) => el("option", { value: o[0] }, o[1])));
  const atual = opcoes.findIndex((o) => o[0] === fusoEscolhido.zona);
  s.selectedIndex = Math.max(0, atual);
  return s;
}
