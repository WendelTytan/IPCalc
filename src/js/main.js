import { loadFooter } from "./components/footer.js";

loadFooter();

/* ============================================================
 * IPv4
 * ============================================================ */
function isValidOctets(o) { 
  return o.length===4 && o.every (
    n => Number.isInteger(n) && n>=0 && n<=255
  ); 
}

function parseIp4(ip){
  const parts = String(ip).trim().split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map(p => /^\d+$/.test(p) ? Number(p) : NaN);
  return isValidOctets(nums) ? nums : null;
}

function octetsToBin(o){
  return o.map(
    n => n.toString(2).padStart(8,"0")
  ); 
}

function binToOctets(bin){
  const clean = String(bin).replace(/[.\s]/g, "");
  if (clean.length !== 32 || !/^[01]+$/.test(clean)) return null;
  return [0,1,2,3].map(
    i => parseInt(clean.slice(i*8, i*8+8), 2)
  );
}

function cidrToMask4(cidr){
  const mask = cidr === 0 ? 0 : (0xffffffff << (32 - cidr)) >>> 0;
  return [
    (mask>>>24)&0xff, 
    (mask>>>16)&0xff, 
    (mask>>>8)&0xff, 
    mask&0xff
  ];
}

function maskToCidr4(mask){
  const bin = octetsToBin(mask).join("");
  const m = bin.match(/^(1*)(0*)$/);
  if (!m) return null;
  return m[1].length;
}

function ipClass(first){
  if (first < 128) return "A";
  if (first < 192) return "B";
  if (first < 224) return "C";
  if (first < 240) return "D (Multicast)";
  return "E (Reservado)";
}

function calculate4(ip, mask){
  const cidr = maskToCidr4(mask) ?? 0;
  const network = ip.map((o,i) => o & mask[i]);
  const wildcard = mask.map(o => 255 - o);
  const broadcast = network.map((o,i) => o | wildcard[i]);
  const totalHosts = cidr >= 32 ? 1 : Math.pow(2, 32 - cidr);
  const usableHosts = cidr >= 31 ? 0 : totalHosts - 2;
  let firstHost=null, lastHost=null;
  if (cidr < 31){
    firstHost = [...network]; firstHost[3]+=1;
    lastHost = [...broadcast]; lastHost[3]-=1;
  }
  return { 
    ipOctets:ip, 
    maskOctets:mask, 
    networkOctets:network, 
    broadcastOctets:broadcast,
    firstHostOctets:firstHost, 
    lastHostOctets:lastHost, cidr, totalHosts, usableHosts,
    wildcardOctets:wildcard, 
    ipClass:ipClass(
      ip[0]
    ) 
  };
}

const formatIp4 = o => o.join(".");
const formatBin4 = o => octetsToBin(o).join(".");

/* ============================================================
 * IPv6
 * ============================================================ */
const V6_MASK = (1n << 128n) - 1n;

function parseIp6(ip){
  if (typeof ip !== "string") return null;
  let s = ip.trim().toLowerCase();
  if (!s) return null;
  // Neutralizador dos ::, para impedir mais de uma ocorrência
  const dc = (s.match(/::/g) || []).length;
  if (dc > 1) return null;
  let head = [], tail = [];
  if (dc === 1){
    const [h, t] = s.split("::");
    head = h ? h.split(":") : [];
    tail = t ? t.split(":") : [];
    const total = head.length + tail.length;
    if (total > 7) return null;
    const fill = new Array(8 - total).fill("0");
    var groups = [...head, ...fill, ...tail];
  } else {
    var groups = s.split(":");
    if (groups.length !== 8) return null;
  }
  const nums = [];
  for (const g of groups){
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    nums.push(parseInt(g, 16));
  }
  return nums;
}

function ip6ToBigInt(groups){
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(g);
  return n;
}
function bigIntToIp6(n){
  const g = [];
  for (let i = 7; i >= 0; i--){
    g.push(Number((n >> BigInt(i*16)) & 0xffffn));
  }
  return g;
}
function ip6ToBin(groups){
  return groups.map(
    g => g.toString(2).padStart(16, "0")
  ).join("");
}
function binToIp6(bin){
  const clean = String(bin).replace(/[:.\s]/g, "");
  if (clean.length !== 128 || !/^[01]+$/.test(clean)) return null;
  const groups = [];
  for (let i = 0; i < 8; i++){
    groups.push(parseInt(clean.slice(i*16, i*16+16), 2));
  }
  return groups;
}
function prefixToMask6(prefix){
  if (prefix === 0) return 0n;
  return (V6_MASK << BigInt(128 - prefix)) & V6_MASK;
}
function maskToPrefix6(maskBig){
  // a mascara tem valores definidos iniciados com 1, e finalizado com 0 ex: 111111:111000
  const bin = maskBig.toString(2).padStart(128, "0");
  const m = bin.match(/^(1*)(0*)$/);
  if (!m) return null;
  return m[1].length;
}
function formatIp6Full(groups){
  return groups.map(g => g.toString(16).padStart(4, "0")).join(":");
}
function formatIp6(groups){
  // RFC 5952
  const hex = groups.map(g => g.toString(16));
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++){
    if (groups[i] === 0){
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen){ bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  }
  if (bestLen < 2) return hex.join(":");
  const left = hex.slice(0, bestStart).join(":");
  const right = hex.slice(bestStart + bestLen).join(":");
  return left + "::" + right;
}
function formatBin6(groups){
  return groups.map(g => g.toString(2).padStart(16, "0")).join(":");
}

function calculate6(ipGroups, prefix){
  const ipBig = ip6ToBigInt(ipGroups);
  const maskBig = prefixToMask6(prefix);
  const networkBig = ipBig & maskBig;
  const wildcardBig = (~maskBig) & V6_MASK;
  const lastBig = networkBig | wildcardBig;
  const total = 1n << BigInt(128 - prefix);
  // Primeiro e ultimo host utilizavel
  let firstHost = null, lastHost = null;
  let usable = 0n;
  if (prefix === 128){
    usable = 1n;
  } else if (prefix === 127){
    usable = 2n;
    firstHost = bigIntToIp6(networkBig);
    lastHost = bigIntToIp6(lastBig);
  } else {
    usable = total - 1n; // todos endereços -1 reservado para rede
    firstHost = bigIntToIp6(networkBig + 1n);
    lastHost = bigIntToIp6(lastBig);
  }
  return {
    version: 6,
    ipGroups,
    maskGroups: bigIntToIp6(maskBig),
    networkGroups: bigIntToIp6(networkBig),
    lastGroups: bigIntToIp6(lastBig),
    wildcardGroups: bigIntToIp6(wildcardBig),
    firstHostGroups: firstHost,
    lastHostGroups: lastHost,
    prefix,
    totalHostsBig: total,
    usableHostsBig: usable,
  };
}

/* ============================================================
 * State
 * ============================================================ */
const state = {
  version: "v4",                   // v4 | v6
  // shared
  mode: "decimal",                 // decimal | binario | hosts
  decimalSubMode: "cidr",          // cidr | mask
  fatiamentoMode: "cidr", 
  // v4
  ipStr: "192.168.1.10",
  cidrStr: "24",
  maskStr: "255.255.255.0",
  ipBin: "11000000.10101000.00000001.00001010",
  maskBin: "11111111.11111111.11111111.00000000",
  hostsStr: "254",
  hostsIpStr: "192.168.1.0",
  // v6
  ip6Str: "2001:db8:abcd:12::1",
  prefix6Str: "120",
  mask6Str: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00",
  ip6Bin: "",
  mask6Bin: "",
  hosts6Str: "254",
  hosts6IpStr: "2001:db8::",
  // Fatiamento ipv4
  fatiaIpStr: "192.168.1.0",
  fatiaCidrBaseStr: "24",
  fatiaCidrNovoStr: "26",
  fatiaRedesStr: "4",
  fatiaHostsStr: "30",
  // Fatiamento ipv6
  fatia6IpStr: "2001:db8::",
  fatia6PrefixBaseStr: "122",
  fatia6PrefixNovoStr: "123",
  fatia6RedesStr: "4",
  fatia6HostsStr: "31", 
};

// Iniciando calculo do ipv6 binario para ter um placeholder
state.ip6Bin = formatBin6(parseIp6(state.ip6Str));
state.mask6Bin = formatBin6(bigIntToIp6(prefixToMask6(120)));

/* ============================================================
 * Helpers
 * ============================================================ */
const esc = s => String(s).replace(
  /[&<>"']/g, c => (
    {
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
    }[c]
  )
);

function fmtBig(n){
  // agrupando casas decimais
  const s = n.toString();
  return s.replace(/\B(?=(\d{3})+(?!\d))/g, ".");
}

//renderizando as cores
function binStringHTML(bin, opts={}){
  const { 
    highlightBits, 
    variant, 
    groupSize=8, 
    sep="." 
  } = opts;

  const colorMap = { 
    network:"text-network", 
    host:"text-host", 
    broadcast:"text-broadcast", 
    default:"text-fg" 
  };

  if (highlightBits === undefined){
    const cls = colorMap[variant || "default"];
    let out = `<code class="font-mono text-[11px] sm:text-sm tracking-tight ${cls} break-all">`;
    for (let i = 0; i < bin.length; i += groupSize){
      if (i > 0) out += `<span class="text-mutedfg">${sep}</span>`;
      out += bin.slice(i, i+groupSize);
    }
    return out + `</code>`;
  }
  let out = `<code class="font-mono text-[11px] sm:text-sm tracking-tight break-all">`;
  for (let i = 0; i < bin.length; i++){
    if (i > 0 && i % groupSize === 0) out += `<span class="text-mutedfg">${sep}</span>`;
    const isNet = i < highlightBits;
    out += `<span class="${isNet ? 'text-network' : 'text-host'}">${bin[i]}</span>`;
  }
  return out + `</code>`;
}

function octetBinHTML(octets, opts={}){
  return binStringHTML(
    octetsToBin(octets).join(""), 
    { ...opts, groupSize:8, sep:"." }
  );
}
function groupBinHTML(groups, opts={}){
  return binStringHTML(
    ip6ToBin(groups), 
    { ...opts, groupSize:16, sep:":" }
  );
}

function ipToInt(ipOctets) {
  return (
    (ipOctets[0] << 24) | 
    (ipOctets[1] << 16) | 
    (ipOctets[2] << 8) |
     ipOctets[3]
    ) >>> 0;
}

function intToIp(intNum) {
  return [
    (intNum >>> 24) & 255, 
    (intNum >>> 16) & 255, 
    (intNum >>> 8) & 255, 
    intNum & 255
  ];
}

/* ============================================================
 * Compute
 * ============================================================ */
function compute(){
  try {
    if (state.version === "v4") 
      return computeV4();
    return computeV6();
  } catch(e){ 
    return { 
      error: "Erro ao calcular." 
    }; 
  }
}

function computeV4(){
  if (state.mode === "decimal"){
    const ip = parseIp4(state.ipStr);
    if (!ip) 
      return { 
        error: "IP inválido. Use o formato 0.0.0.0" 
      };
    if (state.decimalSubMode === "cidr"){
      const cidr = Number(state.cidrStr);
      if (!Number.isInteger(cidr) || cidr < 0 || cidr > 32)
        return { 
          error: "CIDR inválido. Use um valor entre 0 e 32." 
        };
      return { 
        calc: calculate4(ip, cidrToMask4(cidr)) 
      };
    } else {
      const mask = parseIp4(state.maskStr);
      if (!mask) 
        return { 
          error: "Máscara inválida. Use o formato 255.255.255.0" 
        };
      if (maskToCidr4(mask) === null)
        return { 
          error: "Máscara inválida: precisa ter todos os 1s contíguos antes dos 0s." 
        };
      return { 
        calc: calculate4(ip, mask) 
      };
    }
  } else if (state.mode === "binario"){
    const ip = binToOctets(state.ipBin);
    const mask = binToOctets(state.maskBin);
    if (!ip) 
      return { 
        error: "IP binário inválido. Use 32 bits (0/1)." 
      };
    if (!mask) return { 
      error: "Máscara binária inválida. Use 32 bits (0/1)." 
    };
    if (maskToCidr4(mask) === null)
      return { 
        error: "Máscara inválida: precisa ter todos os 1s contíguos antes dos 0s." 
      };
    return { calc: calculate4(ip, mask) };
  } else if (state.mode === "fatiamento") {
    const ip = parseIp4(state.fatiaIpStr);
    const baseCidr = Number(state.fatiaCidrBaseStr);
    let novoCidr;

    if (!ip) return { 
      error: "IP base inválido." 
    };
    if (baseCidr < 0 || baseCidr > 32) return { 
      error: "CIDR base inválido. Use 0 a 32." 
    };

    if (state.fatiamentoMode === "cidr") {
      novoCidr = Number(state.fatiaCidrNovoStr);
      if (novoCidr <= baseCidr || novoCidr > 32) return { 
        error: "O Novo CIDR deve ser MAIOR que o CIDR Original e <= 32." 
      };
    } else if (state.fatiamentoMode === "redes") {
      const redesDesejadas = Number(String(state.fatiaRedesStr).replace(/[.,\s]/g, ""));
      if (!Number.isInteger(redesDesejadas) || redesDesejadas < 1) return { 
        error: "Quantidade de redes deve ser ≥ 1." 
      };
      const bitsEmprestados = Math.ceil(Math.log2(redesDesejadas));
      novoCidr = baseCidr + bitsEmprestados;
      if (novoCidr > 32) return { 
        error: `Para criar ${redesDesejadas} redes, a máscara passaria de /32 (IPv4 esgotado).` 
      };
    } else {
      const reqHosts = Number(String(state.fatiaHostsStr).replace(/[.,\s]/g, ""));
      if (!Number.isInteger(reqHosts) || reqHosts < 1) return { 
        error: "Quantidade de computadores deve ser ≥ 1." 
      };
      
      let hostBits = 0;
      // Precisamos cobrir a qtde de hosts + 2 endereços (Rede e Broadcast)
      while (Math.pow(2, hostBits) - 2 < reqHosts) { hostBits++; }
      novoCidr = 32 - hostBits;
      
      if (novoCidr < baseCidr) return { 
        error: `Para ter ${reqHosts} computadores, a máscara precisaria ser /${novoCidr}. Essa sub-rede é maior que a sua rede original (/${baseCidr}), portanto não cabe.` 
      };
    }

    if (novoCidr >= 31) {
      return { 
        error: `Impossível fatiar: a nova máscara seria /${novoCidr}. Redes /31 e /32 não possuem IPs suficientes para abrigar Hosts e Broadcast.` 
      };
    }

    const bitsEmprestados = novoCidr - baseCidr;
    if (bitsEmprestados > 20) return { 
      error: "Essa divisão gera mais de 1 milhão de sub-redes! Tente um intervalo menor." 
    };
    
    const numSubredes = Math.pow(2, bitsEmprestados);
    const hostBits = 32 - novoCidr;
    const tamanhoSubrede = Math.pow(2, hostBits);

    const maskBase = cidrToMask4(baseCidr);
    const netBase = ip.map((o,i) => o & maskBase[i]);
    const baseInt = ipToInt(netBase);

    const subredes = [];
    const maxDisplay = 256; // Limite visual para não travar o DOM
    
    for(let i = 0; i < Math.min(numSubredes, maxDisplay); i++) {
      const subNetInt = baseInt + (i * tamanhoSubrede);
      const subIp = intToIp(subNetInt);
      
      subredes.push(calculate4(subIp, cidrToMask4(novoCidr))); 
    }

    return { calcFatia: 
      { numSubredes, 
        subredes, 
        maxDisplay, 
        novoCidr, 
        tamanhoSubrede, 
        netBase, 
        baseCidr 
      } 
    };
  } else {
    const ip = parseIp4(state.hostsIpStr);
    const hosts = Number(String(state.hostsStr).replace(/[.,\s]/g, ""));
    if (!ip) 
      return { 
        error: "IP inválido. Use o formato 0.0.0.0" 
      };
    if (!Number.isInteger(hosts) || hosts < 1)
      return { 
        error: "Quantidade de hosts deve ser um inteiro ≥ 1." 
      };
    const needed = hosts + 2;
    let hostBits = 0;
    while (Math.pow(2, hostBits) < needed) hostBits++;
    if (hostBits > 32) 
      return { 
        error: "Quantidade de hosts excede o espaço IPv4."
      };
    const cidr = 32 - hostBits;
    return { 
      calc: calculate4(ip, cidrToMask4(cidr)), 
      hostBits 
    };
  }
}

function computeV6(){
  if (state.mode === "decimal"){
    const ip = parseIp6(state.ip6Str);
    if (!ip) 
      return { 
        error: "IPv6 inválido. Ex.: 2001:db8::1" 
      };
    if (state.decimalSubMode === "cidr"){
      const p = Number(state.prefix6Str);
      if (!Number.isInteger(p) || p < 0 || p > 128)
        return { 
          error: "Prefixo inválido. Use um valor entre 0 e 128." 
        };
      return { 
        calc: calculate6(ip, p) 
      };
    } else {
      // máscara IPv6 manual (formato hextet)
      const m = parseIp6(state.mask6Str);
      if (!m) return { 
        error: "Máscara IPv6 inválida. Ex.: ffff:ffff:ffff:ffff::" 
      };
      const p = maskToPrefix6(ip6ToBigInt(m));
      if (p === null) return { 
        error: "Máscara inválida: precisa ter todos os 1s contíguos antes dos 0s." 
      };
      return { 
        calc: calculate6(ip, p) 
      };
    }
  } else if (state.mode === "binario"){
    const ip = binToIp6(state.ip6Bin);
    if (!ip) return { 
      error: "IP binário inválido. Use 128 bits (0/1)." 
    };
    // Mascara binária
    const mask = binToIp6(state.mask6Bin);
    if (!mask) return { 
      error: "Máscara binária inválida. Use 128 bits (0/1)." 
    };
    const p = maskToPrefix6(ip6ToBigInt(mask));
    if (p === null) return { 
      error: "Máscara inválida: precisa ter todos os 1s contíguos antes dos 0s." 
    };
    return { 
      calc: calculate6(ip, p) 
    };
  } else if (state.mode === "fatiamento") {
    const ip = parseIp6(state.fatia6IpStr);
    const basePrefix = Number(state.fatia6PrefixBaseStr);
    let novoPrefix;

    if (!ip) return { 
      error: "IPv6 base inválido. Ex.: 2001:db8::" 
    };
    if (basePrefix < 0 || basePrefix > 128) return { 
      error: "Prefixo inválido. Use 0 a 128." 
    };

    if (state.fatiamentoMode === "cidr") {
      novoPrefix = Number(state.fatia6PrefixNovoStr);
      if (novoPrefix <= basePrefix || novoPrefix > 128) return { 
        error: "O Novo Prefixo deve ser MAIOR que o Prefixo Original." 
      };
    } else if (state.fatiamentoMode === "redes") {
      let redesDesejadas;
      try { 
        redesDesejadas = BigInt(String(state.fatia6RedesStr).replace(/[.,\s]/g, "")); 
      } catch(e) { 
        return { 
          error: "Quantidade inválida." 
        }; 
      }
      if (redesDesejadas < 1n) return { 
        error: "Quantidade de redes deve ser ≥ 1." 
      };
      let bitsEmprestadosCalc = 0;
      while ((1n << BigInt(bitsEmprestadosCalc)) < redesDesejadas) { bitsEmprestadosCalc++; }
      novoPrefix = basePrefix + bitsEmprestadosCalc;
      if (novoPrefix > 128) return { 
        error: "Excede o espaço de 128 bits do IPv6." 
      };
    } else {
      // MODO POR HOSTS (NOVO)
      let reqHostsBig;
      try { 
        reqHostsBig = BigInt(String(state.fatia6HostsStr).replace(/[.,\s]/g, "")); 
      } catch(e) { 
        return { 
          error: "Quantidade inválida." 
        }; 
      }
      if (reqHostsBig < 1n) return { 
        error: "Quantidade de computadores deve ser ≥ 1." 
      };
      
      let hostBits = 0;
      // Precisamos cobrir a qtde de hosts (adiciona +1 para reservar o ID da rede, comportamento típico IPv6)
      while ((1n << BigInt(hostBits)) < reqHostsBig + 1n) { hostBits++; }
      novoPrefix = 128 - hostBits;
      
      if (novoPrefix < basePrefix) return { 
        error: `Para comportar ${reqHostsBig} endereços, o prefixo seria /${novoPrefix}. Essa sub-rede é maior que a sua rede original (/${basePrefix}), portanto não cabe.` 
        };
    }

    if (novoPrefix >= 127) {
      return { 
        error: `Impossível fatiar: o novo prefixo seria /${novoPrefix}. Prefixos /127 e /128 são reservados para links ponto-a-ponto ou loopback, não comportando sub-redes padrão.` 
      };
    }

    const bitsEmprestados = novoPrefix - basePrefix;
    if (bitsEmprestados > 32) return { 
      error: "Essa divisão é colossal! Tente um intervalo menor para não sobrecarregar o navegador." 
    };
    
    const numSubredes = 1n << BigInt(bitsEmprestados);
    const hostBits = 128 - novoPrefix;
    const tamanhoSubrede = 1n << BigInt(hostBits);

    const ipBig = ip6ToBigInt(ip);
    const maskBaseBig = prefixToMask6(basePrefix);
    const netBaseBig = ipBig & maskBaseBig;

    const subredes = [];
    const maxDisplay = 256; 
    const limit = numSubredes > BigInt(maxDisplay) ? BigInt(maxDisplay) : numSubredes;

    for (let i = 0n; i < limit; i++) {
      const subNetBig = netBaseBig + (i * tamanhoSubrede);
      const subIpGroups = bigIntToIp6(subNetBig);
      subredes.push(calculate6(subIpGroups, novoPrefix));
    }

    return { calcFatia6: { 
      numSubredes, 
      subredes, 
      maxDisplay, 
      novoPrefix, 
      tamanhoSubrede, 
      netBase: bigIntToIp6(netBaseBig), basePrefix 
    } 
  };
  } else {
    const ip = parseIp6(state.hosts6IpStr);
    if (!ip) return { 
      error: "IPv6 inválido. Ex.: 2001:db8::" 
    };
    let hostsBig;
    try { 
      hostsBig = BigInt(String(state.hosts6Str).replace(/[.,\s]/g, "")); 
    } catch(e) { 
      return { 
        error: "Quantidade de hosts inválida." 
      }; 
    }
    if (hostsBig < 1n) return { 
      error: "Quantidade de hosts deve ser ≥ 1." 
    };
    
    const needed = hostsBig + 1n;
    let hostBits = 0;
    while ((1n << BigInt(hostBits)) < needed){
      hostBits++;
      if (hostBits > 128) 
      return { 
        error: "Quantidade de hosts excede o espaço IPv6." 
      };
    }
    const prefix = 128 - hostBits;
    return { calc: calculate6(ip, prefix), hostBits };
  }
}

/* ============================================================
 * Render
 * ============================================================ */
const inputCls = "w-full px-4 py-3 rounded-lg bg-input border border-border font-mono text-base sm:text-lg focus:outline-none focus:ring-2 focus:ring-ring";
const inputSub = "px-4 py-3 rounded-lg bg-input border border-border font-mono text-base sm:text-lg focus:outline-none focus:ring-2 focus:ring-ring";
const labelCls = "block text-xs font-mono uppercase tracking-wider text-mutedfg mb-2";

function renderVersionSwitch(){
  const versions = [
    ["v4","IPv4"],
    ["v6","IPv6"]
  ];
  return `
    <div class="flex justify-center mb-6">
      <div class="inline-flex p-1 rounded-full bg-card border border-border">
        ${versions.map(([v,label]) => `
          <button data-version="${v}" class="px-6 py-2 text-sm font-semibold rounded-full transition-all ${
            state.version === v ? 'bg-accent text-primaryfg shadow-lg shadow-accent/20' : 'text-mutedfg hover:text-fg'
          }">${label}</button>
        `).join("")}
      </div>
    </div>`;
}

function renderModeSwitch(){
  const modes = [
    ["decimal", state.version==="v6" ? "IPv6 + /Prefixo" : "IP + /CIDR"],
    ["binario","Binário"],
    ["hosts","Por nº de Hosts"],
    ["fatiamento", "Sub-Redes"]
  ];
  return `
    <div class="flex justify-center mb-8">
      <div class="inline-flex p-1 rounded-full bg-card border border-border flex-wrap">
        ${modes.map(([m,label]) => `
          <button data-mode="${m}" class="px-5 py-2 text-sm font-medium rounded-full transition-all ${
            state.mode === m ? 'bg-primary text-primaryfg shadow-lg shadow-primary/20' : 'text-mutedfg hover:text-fg'
          }">${label}</button>
        `).join("")}
      </div>
    </div>`;
}

function renderInputs(){
  const isV6 = state.version === "v6";
  if (state.mode === "decimal"){
    const submodes = [
      ["cidr", isV6 ? "/Prefixo" : "/CIDR"],
      ["mask","Máscara"]
    ];
    const ipBind = isV6 ? "ip6Str" : "ipStr";
    const ipVal = isV6 ? state.ip6Str : state.ipStr;
    const ipPh = isV6 ? "2001:db8:abcd:12::1" : "192.168.1.10";
    const cidrBind = isV6 ? "prefix6Str" : "cidrStr";
    const cidrVal = isV6 ? state.prefix6Str : state.cidrStr;
    const cidrMax = isV6 ? 128 : 32;
    const maskPh = isV6 ? "ffff:ffff:ffff:ffff::" : "255.255.255.0";
    return `
      <div class="space-y-4">
        <div class="flex gap-2">
          ${submodes.map(([sm,label]) => `
            <button data-submode="${sm}" class="px-3 py-1 text-xs font-mono uppercase tracking-wider rounded-full border transition-all 
            ${state.decimalSubMode === sm 
              ? 'bg-primary text-primaryfg border-primary' 
              : 'bg-card text-mutedfg border-border hover:text-fg'
            }">${label}</button>
          `).join("")}
        </div>
        <div class="grid sm:grid-cols-[1fr_auto] gap-4 items-end">
          <div>
            <label class="${labelCls}">Endereço ${isV6?"IPv6":"IP"}</label>
            <input 
            data-bind="${ipBind}" 
            value="${esc(ipVal)}" 
            placeholder="${ipPh}" 
            class="${inputCls}" 
            />
          </div>
          ${state.decimalSubMode === "cidr" ? `
            <div>
              <label class="${labelCls}">${isV6?"/Prefixo":"/CIDR"}</label>
              <div class="flex items-center gap-2">
                <span class="font-mono text-lg text-primary">/</span>
                <input 
                data-bind="${cidrBind}" 
                type="text"
                inputmode="numeric"
                min="0" 
                max="${cidrMax}" 
                value="${esc(cidrVal)}" 
                class="w-24 ${inputCls}" 
                />
              </div>
            </div>
          ` : `
            <div>
              <label class="${labelCls}">Máscara</label>
              <input 
              data-bind="${isV6?"mask6Str":"maskStr"}" 
              value="${esc(isV6?state.mask6Str:state.maskStr)}" 
              placeholder="${maskPh}" 
              class="w-24 ${inputCls}" 
              />
            </div>
          `}
        </div>
      </div>`;
  }
  if (state.mode === "binario"){
    if (isV6){
      // verificando bits do ipv6 para não estourar
      if (!state.mask6Bin || state.mask6Bin.replace(/[:.\s]/g,"").length !== 128){
        state.mask6Bin = formatBin6(bigIntToIp6(prefixToMask6(64)));
      }
      return `
        <div class="space-y-4">
          <div>
            <label class="${labelCls}">IPv6 em binário (128 bits — separadores opcionais)</label>
            <input 
            data-bind="ip6Bin" 
            value="${esc(state.ip6Bin)}" 
            placeholder="0010000000000001:..." 
            class="${inputCls} text-xs sm:text-sm" 
            />
          </div>
          <div>
            <label class="${labelCls}">Máscara em binário (128 bits)</label>
            <input 
            data-bind="mask6Bin" 
            value="${esc(state.mask6Bin)}" 
            class="${inputCls} text-xs sm:text-sm" 
            />
          </div>
        </div>`;
    }
    return `
      <div class="space-y-4">
        <div>
          <label class="${labelCls}">IP em binário (32 bits — pontos opcionais)</label>
          <input 
          data-bind="ipBin" 
          value="${esc(state.ipBin)}" 
          placeholder="11000000.10101000.00000001.00001010" 
          class="${inputCls} text-sm sm:text-base" 
          />
        </div>
        <div>
          <label class="${labelCls}">Máscara em binário (32 bits)</label>
          <input 
          data-bind="maskBin" 
          value="${esc(state.maskBin)}" 
          placeholder="11111111.11111111.11111111.00000000" 
          class="${inputCls} text-sm sm:text-base" 
          />
        </div>
      </div>`;
  } 
  if (state.mode === "fatiamento") {
    const fatiaSubmodes = [
      ["cidr", isV6 ? "Por Novo Prefixo" : "Por Novo CIDR"],
      ["redes", "Por Nº de Redes"],
      ["hosts", "Por Nº de Hosts"]
    ];
    
    const baseCidrBind = isV6 ? "fatia6PrefixBaseStr" : "fatiaCidrBaseStr";
    const baseCidrVal = isV6 ? state.fatia6PrefixBaseStr : state.fatiaCidrBaseStr;
    const ipBind = isV6 ? "fatia6IpStr" : "fatiaIpStr";
    const ipVal = isV6 ? state.fatia6IpStr : state.fatiaIpStr;
    const ipPh = isV6 ? "2001:db8::" : "192.168.1.0";
    const maxCidr = isV6 ? 128 : 32;

    return `
      <div class="space-y-4">
        <div class="flex flex-wrap gap-2">
          ${fatiaSubmodes.map(([sm,label]) => `
            <button data-fatiasub="${sm}" class="px-3 py-1 text-xs font-mono uppercase tracking-wider rounded-full border transition-all 
            ${state.fatiamentoMode === sm 
              ? 'bg-primary text-primaryfg border-primary' 
              : 'bg-card text-mutedfg border-border hover:text-fg'
            }">${label}</button>
          `).join("")}
        </div>
        
        <div class="grid sm:grid-cols-[1fr_auto_auto] gap-4 items-end">
          <div>
            <label class="${labelCls}">${isV6 ? "IPv6" : "IP"} da Rede Original</label>
            <input data-bind="${ipBind}" value="${esc(ipVal)}" placeholder="${ipPh}" class="${inputCls}" />
          </div>
          <div>
            <label class="${labelCls}">${isV6 ? "Prefixo Base" : "CIDR Original"}</label>
            <div class="flex items-center gap-2">
              <span class="font-mono text-lg text-primary">/</span>
              <input data-bind="${baseCidrBind}" type="text" inputmode="numeric" min="0" max="${maxCidr}" value="${esc(baseCidrVal)}" class="w-20 ${inputSub}" />
            </div>
          </div>
          
          ${state.fatiamentoMode === "cidr" ? `
            <div>
              <label class="${labelCls}">Novo ${isV6 ? "Prefixo" : "CIDR"}</label>
              <div class="flex items-center gap-2">
                <span class="font-mono text-lg text-network">/</span>
                <input data-bind="${isV6 ? "fatia6PrefixNovoStr" : "fatiaCidrNovoStr"}" type="text" inputmode="numeric" min="1" max="${maxCidr}" value="${esc(isV6 ? state.fatia6PrefixNovoStr : state.fatiaCidrNovoStr)}" class="w-20 ${inputSub}" />
              </div>
            </div>
          ` : state.fatiamentoMode === "redes" ? `
            <div>
              <label class="${labelCls}">Qtd. Sub-redes</label>
              <input data-bind="${isV6 ? "fatia6RedesStr" : "fatiaRedesStr"}" type="text" inputmode="numeric" min="1" value="${esc(isV6 ? state.fatia6RedesStr : state.fatiaRedesStr)}" class="w-28 ${inputSub}" placeholder="Ex: 4" />
            </div>
          ` : `
            <div>
              <label class="${labelCls}">Computadores (Hosts)</label>
              <input data-bind="${isV6 ? "fatia6HostsStr" : "fatiaHostsStr"}" type="text" inputmode="numeric" min="1" value="${esc(isV6 ? state.fatia6HostsStr : state.fatiaHostsStr)}" class="w-32 ${inputSub}" placeholder="Ex: 30" />
            </div>
          `}
        </div>
        <p class="mt-4 text-xs text-mutedfg font-mono">
          Divide a rede original em múltiplas sub-redes menores. ${isV6 ? "Exibiremos no máximo as 256 primeiras para IPv6." : ""}
        </p>
      </div>`;
  }
  // hosts
  if (isV6){
    return `
      <div class="grid sm:grid-cols-[1fr_auto] gap-4 items-end">
        <div>
          <label class="${labelCls}">IPv6 base da rede</label>
          <input 
          data-bind="hosts6IpStr" 
          value="${esc(state.hosts6IpStr)}" 
          placeholder="2001:db8::" 
          class="${inputCls}" 
          />
        </div>
        <div>
          <label class="${labelCls}">Hosts necessários</label>
          <input 
          data-bind="hosts6Str" 
          value="${esc(state.hosts6Str)}" 
          class="w-24 ${inputCls}" 
          />
        </div>
        <p class="sm:col-span-2 text-xs text-mutedfg font-mono">
          Aceita números muito grandes (BigInt). Calcula o menor prefixo que comporta os hosts.
        </p>
      </div>`;
  }
  return `
    <div class="grid sm:grid-cols-[1fr_auto] gap-4 items-end">
      <div>
        <label class="${labelCls}">IP base da rede</label>
        <input 
        data-bind="hostsIpStr" 
        value="${esc(state.hostsIpStr)}" 
        placeholder="192.168.1.0" 
        class="${inputCls}" 
        />
      </div>
      <div>
        <label class="${labelCls}">Hosts necessários</label>
        <input 
        data-bind="hostsStr" 
        type="text"
        inputmode="numeric" 
        min="1" 
        value="${esc(state.hostsStr)}" 
        class="w-24 ${inputCls}" 
        />
      </div>
      <p class="sm:col-span-2 text-xs text-mutedfg font-mono">
        Calcula a menor máscara que comporta os hosts (reservando rede + broadcast).
      </p>
    </div>`;
}

function renderResults(){
  const r = compute();
  if (r.error){
    return `<div class="rounded-xl border border-destructive/40 bg-destructive/10 text-fg p-4 text-sm">${esc(r.error)}</div>`;
  }
  if (r.calcFatia) return renderFatiamento4(r.calcFatia);
  if (r.calcFatia6) return renderFatiamento6(r.calcFatia6);
  
  return state.version === "v6" ? renderResults6(r.calc) : renderResults4(r.calc);
}

function renderResults4(calc){
  const rows = [
    { 
      label:"IP", 
      octets:calc.ipOctets, 
      variant:"default", 
      highlight:true 
    },
    { 
      label:"Máscara", 
      octets:calc.maskOctets, 
      variant:"network" 
    },
    { 
      label:"ID da Rede", 
      octets:calc.networkOctets, 
      variant:"network", 
      highlight:true 
    },
    { 
      label:"Broadcast", 
      octets:calc.broadcastOctets, 
      variant:"broadcast", 
      highlight:true 
    },
    { 
      label:"Wildcard", 
      octets:calc.wildcardOctets, 
      variant:"host" 
    },
  ];
  if (calc.firstHostOctets && calc.lastHostOctets){
    rows.push({ 
      label:"Primeiro Host", 
      octets:calc.firstHostOctets, 
      variant:"default", 
      highlight:true 
    });
    rows.push({ 
      label:"Último Host", 
      octets:calc.lastHostOctets, 
      variant:"default", 
      highlight:true 
    });
  }
  const stat = (label,value) => `
    <div class="rounded-xl border border-border bg-card p-4">
      <div class="text-[10px] font-mono uppercase tracking-wider text-mutedfg">${esc(label)}</div>
      <div class="text-xl font-semibold mt-1 truncate">${esc(value)}</div>
    </div>`;

  const rowHTML = r => {
    const dec = formatIp4(r.octets);
    const bin = r.highlight 
    ? octetBinHTML(r.octets, { highlightBits: calc.cidr }) 
    : octetBinHTML(r.octets, { variant: r.variant });
    return `
      <div class="grid grid-cols-[110px_1fr] sm:grid-cols-[140px_180px_1fr] gap-x-4 px-4 sm:px-6 py-3 items-center hover:bg-secondary/30 transition-colors">
        <div class="text-sm font-medium">${esc(r.label)}</div>
        <div class="hidden sm:block font-mono text-sm text-mutedfg">${esc(dec)}</div>
        <div class="col-span-2 sm:col-span-1 mt-1 sm:mt-0 overflow-x-auto">
          <div class="sm:hidden font-mono text-xs text-mutedfg mb-1">${esc(dec)}</div>
          ${bin}
        </div>
      </div>`;
  };
  return `
    <div class="space-y-6 fade-in">
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
        ${stat("CIDR","/"+calc.cidr)}
        ${stat("Classe", calc.ipClass)}
        ${stat("Hosts utilizáveis", calc.usableHosts.toLocaleString("pt-BR"))}
        ${stat("Total de endereços", calc.totalHosts.toLocaleString("pt-BR"))}
      </div>
      <div class="rounded-2xl border border-border bg-card overflow-hidden">
        <div class="grid grid-cols-[110px_1fr] sm:grid-cols-[140px_180px_1fr] gap-x-4 px-4 sm:px-6 py-3 border-border bg-secondary/50 text-xs font-mono uppercase tracking-wider text-mutedfg">
          <div>Campo</div>
          <div class="hidden sm:block">Decimal</div>
          <div>Binário</div>
        </div>
        <div class="divide-y divide-border">
          ${rows.map(rowHTML).join("")}
        </div>
      </div>
      <div class="rounded-xl border border-border bg-card p-4 sm:p-6">
        <div class="text-xs font-mono uppercase tracking-wider text-mutedfg mb-2">Notação CIDR</div>
        <div class="font-mono text-lg sm:text-xl text-primary">${formatIp4(calc.networkOctets)}/${calc.cidr}</div>
        <div class="font-mono text-xs text-mutedfg mt-1 break-all">${formatBin4(calc.networkOctets)}</div>
      </div>
    </div>`;
}

function renderFatiamento4(fatia) {
  const stat = (label,value) => `
    <div class="flex-1 min-w-[140px] overflow-hidden rounded-xl border border-border bg-card p-4">
      <div class="text-[10px] font-mono uppercase tracking-wider text-mutedfg">${esc(label)}</div>
      <div class="text-xl font-semibold mt-1 truncate" title="${esc(value)}">${esc(value)}</div>
    </div>`;

  const rowsHtml = fatia.subredes.map((calc, i) => `
    <div class="grid grid-cols-[40px_1fr_1fr_1fr] sm:grid-cols-[60px_1fr_1fr_1fr_1fr] gap-x-4 px-4 py-3 hover:bg-secondary/30 transition-colors text-sm font-mono items-center">
      <div class="text-mutedfg">#${i}</div>
      <div class="text-network font-semibold">${formatIp4(calc.networkOctets)}</div>
      <div class="hidden sm:block text-fg">${calc.firstHostOctets ? formatIp4(calc.firstHostOctets) : '<span class="text-mutedfg">N/A</span>'}</div>
      <div class="hidden sm:block text-fg">${calc.lastHostOctets ? formatIp4(calc.lastHostOctets) : '<span class="text-mutedfg">N/A</span>'}</div>
      <div class="text-broadcast">${formatIp4(calc.broadcastOctets)}</div>
    </div>
  `).join("");

  const mascaraNovaStr = formatIp4(cidrToMask4(fatia.novoCidr));

  return `
    <div class="space-y-6 fade-in">
      <div class="flex flex-wrap gap-3">
        ${stat("Rede Base", formatIp4(fatia.netBase) + "/" + fatia.baseCidr)}
        ${stat("Sub-redes", fatia.numSubredes.toLocaleString("pt-BR"))}
        ${stat("Novo CIDR", "/" + fatia.novoCidr)}
        ${stat("Nova Máscara", mascaraNovaStr)}
        ${stat("Hosts/Rede", (fatia.tamanhoSubrede > 2 ? fatia.tamanhoSubrede - 2 : 0).toLocaleString("pt-BR"))}
      </div>

      <div class="rounded-2xl border border-border bg-card overflow-hidden">
        <div class="grid grid-cols-[40px_1fr_1fr_1fr] sm:grid-cols-[60px_1fr_1fr_1fr_1fr] gap-x-4 px-4 py-3 border-border bg-secondary/50 text-xs font-mono uppercase tracking-wider text-mutedfg">
          <div>Nº</div>
          <div>ID da Rede</div>
          <div class="hidden sm:block">Primeiro Host</div>
          <div class="hidden sm:block">Último Host</div>
          <div>Broadcast</div>
        </div>
        <div class="divide-y divide-border">
          ${rowsHtml}
        </div>
        ${fatia.numSubredes > fatia.maxDisplay ? `
          <div class="p-4 text-center text-xs text-mutedfg bg-secondary/20">
            Mostrando as primeiras ${fatia.maxDisplay} de ${fatia.numSubredes.toLocaleString("pt-BR")} sub-redes para otimização de performance.
          </div>
        ` : ""}
      </div>
    </div>`;
}

function renderFatiamento6(fatia) {
  const stat = (label,value) => `
    <div class="flex-1 min-w-[150px] overflow-hidden rounded-xl border border-border bg-card p-4">
      <div class="text-[10px] font-mono uppercase tracking-wider text-mutedfg">${esc(label)}</div>
      <div class="text-lg sm:text-xl font-semibold mt-1 truncate" title="${esc(value)}">${esc(value)}</div>
    </div>`;

  const rowsHtml = fatia.subredes.map((calc, i) => `
    <div class="grid grid-cols-[40px_1fr] sm:grid-cols-[60px_1fr_1fr] gap-4 px-4 py-3 hover:bg-secondary/30 transition-colors text-sm font-mono items-center border-border/50 last:border-0">
      <div class="text-mutedfg">#${i}</div>
      <div class="space-y-1 min-w-0">
        <div class="text-xs text-mutedfg uppercase">ID da Rede</div>
        <div class="text-network font-semibold break-all">${formatIp6(calc.networkGroups)}</div>
      </div>
      <div class="space-y-1 min-w-0">
        <div class="text-xs text-mutedfg uppercase">Último Endereço</div>
        <div class="text-broadcast break-all">${formatIp6(calc.lastGroups)}</div>
      </div>
    </div>
  `).join("");

  const mascaraNovaStr = formatIp6(bigIntToIp6(prefixToMask6(fatia.novoPrefix)));

  return `
    <div class="space-y-6 fade-in">
      <div class="flex flex-wrap gap-3">
        ${stat("Rede Base", formatIp6(fatia.netBase) + "/" + fatia.basePrefix)}
        ${stat("Sub-redes", fmtBig(fatia.numSubredes))}
        ${stat("Novo Prefixo", "/" + fatia.novoPrefix)}
        ${stat("Nova Máscara", mascaraNovaStr)}
        ${stat("Total/Rede", fmtBig(fatia.tamanhoSubrede))}
      </div>

      <div class="rounded-2xl border border-border bg-card overflow-hidden">
        <div class="divide-y divide-border">
          ${rowsHtml}
        </div>
        ${fatia.numSubredes > BigInt(fatia.maxDisplay) ? `
          <div class="p-4 text-center text-xs text-mutedfg bg-secondary/20 font-mono">
            Mostrando apenas as primeiras ${fatia.maxDisplay} de ${fmtBig(fatia.numSubredes)} sub-redes.
          </div>
        ` : ""}
      </div>
    </div>`;
}

function renderResults6(calc){
  const rows = [
    { 
      label:"IP", 
      groups:calc.ipGroups, 
      variant:"default", 
      highlight:true 
    },
    { 
      label:"Máscara", 
      groups:calc.maskGroups, 
      variant:"network" 
    },
    { 
      label:"ID da Rede", 
      groups:calc.networkGroups, 
      variant:"network", 
      highlight:true 
    },
    { 
      label:"Último endereço", 
      groups:calc.lastGroups, 
      variant:"broadcast", 
      highlight:true 
    },
    { 
      label:"Wildcard", 
      groups:calc.wildcardGroups, 
      variant:"host" 
    },
  ];
  if (calc.firstHostGroups && calc.lastHostGroups){
    rows.push({ 
      label:"Primeiro Host", 
      groups:calc.firstHostGroups, 
      variant:"default", 
      highlight:true 
    });
    rows.push({ 
      label:"Último Host", 
      groups:calc.lastHostGroups, 
      variant:"default", 
      highlight:true 
    });
  }
  const stat = (label,value) => `
    <div class="rounded-xl border border-border bg-card p-4 min-w-0">
      <div class="text-[10px] font-mono uppercase tracking-wider text-mutedfg">${esc(label)}</div>
      <div class="text-lg sm:text-xl font-semibold mt-1 truncate" title="${esc(value)}">${esc(value)}</div>
    </div>`;
  const rowHTML = r => {
    const compact = formatIp6(r.groups);
    const full = formatIp6Full(r.groups);
    const bin = r.highlight 
    ? groupBinHTML(r.groups, { highlightBits: calc.prefix }) 
    : groupBinHTML(r.groups, { variant: r.variant });
    return `
      <div class="grid grid-cols-1 sm:grid-cols-[140px_1fr] gap-x-4 gap-y-1 px-4 sm:px-6 py-3 hover:bg-secondary/30 transition-colors">
        <div class="text-sm font-medium">${esc(r.label)}</div>
        <div class="min-w-0 space-y-1">
          <div class="font-mono text-sm text-fg break-all">${esc(compact)}</div>
          <div class="font-mono text-[11px] text-mutedfg break-all">${esc(full)}</div>
          <div class="overflow-x-auto">${bin}</div>
        </div>
      </div>`;
  };
  return `
    <div class="space-y-6 fade-in">
      <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
        ${stat("Prefixo","/"+calc.prefix)}
        ${stat("Hosts utilizáveis", fmtBig(calc.usableHostsBig))}
        ${stat("Total de endereços", fmtBig(calc.totalHostsBig))}
      </div>
      <div class="rounded-2xl border border-border bg-card overflow-hidden">
        <div class="hidden sm:grid grid-cols-[140px_1fr] gap-x-4 px-6 py-3 border-border bg-secondary/50 text-xs font-mono uppercase tracking-wider text-mutedfg">
          <div>Campo</div>
          <div>Compacto · Completo · Binário</div>
        </div>
        <div class="divide-y divide-border">
          ${rows.map(rowHTML).join("")}
        </div>
      </div>
      <div class="rounded-xl border border-border bg-card p-4 sm:p-6">
        <div class="text-xs font-mono uppercase tracking-wider text-mutedfg mb-2">Notação CIDR</div>
        <div class="font-mono text-lg sm:text-xl text-primary break-all">${formatIp6(calc.networkGroups)}/${calc.prefix}</div>
        <div class="font-mono text-xs text-mutedfg mt-1 break-all">${formatIp6Full(calc.networkGroups)}</div>
      </div>
    </div>`;
}

function render(){
  const app = document.getElementById("app");
  const active = document.activeElement;
  const focusBind = active && active.dataset && active.dataset.bind;
  const selStart = active && 'selectionStart' in active ? active.selectionStart : null;
  const selEnd = active && 'selectionEnd' in active ? active.selectionEnd : null;

  app.innerHTML = `
    <div class="w-full max-w-5xl mx-auto px-4 sm:px-6 py-10 sm:py-16">
      <header class="mb-10 text-center">
        <h1 class="text-3xl sm:text-5xl font-bold tracking-tight bg-gradient-to-br from-primary via-accent to-primary bg-clip-text text-transparent">
          Calculadora de Redes
        </h1>
        <p class="mt-3 text-mutedfg max-w-xl mx-auto">
          IPv4 e IPv6: calcule máscara, ID de rede, broadcast/último endereço e hosts — em decimal/hex, binário, ou pelo número de hosts & Sub-redes.
        </p>
      </header>
      ${renderVersionSwitch()}
      ${renderModeSwitch()}
      <div class="rounded-2xl border border-border bg-card p-6 sm:p-8 shadow-2xl shadow-black/20">
        ${renderInputs()}
      </div>
      <div class="mt-8">${renderResults()}</div>
      <footer class="mt-12 text-center text-xs text-mutedfg font-mono">
        <span class="inline-flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-network"></span> bits de rede
          <span class="w-2 h-2 rounded-full bg-host ml-3"></span> bits de host
        </span>
      </footer>
    </div>
  `;

  app.querySelectorAll("[data-version]").forEach(btn => {
    btn.addEventListener("click", () => {
      state.version = btn.dataset.version;
      // resetando submodo para evitar inconsistências (ex: máscara CIDR > 32 no IPv4)
      state.decimalSubMode = "cidr";
      render();
    });
  });
  app.querySelectorAll("[data-mode]").forEach(btn => {
    btn.addEventListener("click", () => { 
      state.mode = btn.dataset.mode; render(); 
    });
  });
  app.querySelectorAll("[data-submode]").forEach(btn => {
    btn.addEventListener("click", () => { 
      state.decimalSubMode = btn.dataset.submode; render(); 
    });
  });
  app.querySelectorAll("[data-fatiasub]").forEach(btn => {
    btn.addEventListener("click", () => { 
      state.fatiamentoMode = btn.dataset.fatiasub; render(); 
    });
  });
  app.querySelectorAll("[data-bind]").forEach(inp => {
    inp.addEventListener("input", e => { 
      state[inp.dataset.bind] = e.target.value; render(); 
    });
  });

  if (focusBind){
    const next = app.querySelector(`[data-bind="${focusBind}"]`);
    if (next){
      next.focus();
      if (selStart !== null) { 
        try { 
          next.setSelectionRange(selStart, selEnd); 
        } catch(_){} 
      }
    }
  }
}

render();