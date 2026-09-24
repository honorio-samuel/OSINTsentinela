/* ==========================================================================
   SCT // CYBER-OSINT MODULE — núcleo compartilhado
   Terminal de saída, requisições com timeout, validações e formatação.
   Tudo roda no navegador: não existe servidor próprio e nada é armazenado.
   ========================================================================== */
'use strict';

const SCT = {
    TIMEOUT_MS: 12000,
    modules: {}
};

/* --------------------------------------------------------------------------
   Terminal: escreve linhas tipadas e guarda uma cópia em texto para o relatório
   -------------------------------------------------------------------------- */
const LINE_PREFIX = {
    cmd: '$ ',
    head: '── ',
    info: '',
    data: '   ',
    ok: '✔ ',
    warn: '⚠ ',
    err: '✖ ',
    explain: '💡 ',
    shield: '🛡 '
};

class Terminal {
    constructor(el) {
        this.el = el;
        this.entries = [];
        this.target = '';
    }

    clear() {
        this.el.replaceChildren();
        this.entries = [];
    }

    idle(message) {
        this.clear();
        const p = document.createElement('p');
        p.className = 'line-log line-idle';
        p.textContent = message;
        this.el.appendChild(p);
    }

    /* parts: strings, { text, href } para links ou { text, action } para botões de pivô */
    log(type, ...parts) {
        const p = document.createElement('p');
        p.className = `line-log line-${type}`;

        const time = new Date().toLocaleTimeString('pt-BR');
        const ts = document.createElement('span');
        ts.className = 'ts';
        ts.textContent = time;
        p.appendChild(ts);

        const prefix = LINE_PREFIX[type] ?? '';
        let plain = prefix;
        p.appendChild(document.createTextNode(prefix));

        for (const part of parts) {
            if (part === null || part === undefined || part === '') continue;

            if (typeof part === 'string' || typeof part === 'number') {
                p.appendChild(document.createTextNode(String(part)));
                plain += part;
            } else if (part.href) {
                const a = document.createElement('a');
                a.href = part.href;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.textContent = part.text || part.href;
                p.appendChild(a);
                plain += part.text && part.text !== part.href ? `${part.text} <${part.href}>` : part.href;
            } else if (part.action) {
                const b = document.createElement('button');
                b.type = 'button';
                b.className = 'pivot-btn';
                b.textContent = part.text;
                b.addEventListener('click', part.action);
                p.appendChild(b);
                plain += `[${part.text}]`;
            }
        }

        this.el.appendChild(p);
        this.entries.push(`[${time}] ${plain}`);
        this.el.scrollTop = this.el.scrollHeight;
        return p;
    }

    /* Conteúdo que vai só para o relatório .txt (ex.: listas longas) */
    note(text) {
        this.entries.push(`           ${text}`);
    }

    toText(title) {
        return [
            'SCT // CYBER-OSINT MODULE — RELATÓRIO',
            `Módulo: ${title}`,
            `Alvo: ${this.target || '-'}`,
            `Gerado em: ${new Date().toLocaleString('pt-BR')}`,
            'Uso educacional. Todas as informações vieram de fontes públicas (reconhecimento passivo).',
            ''.padEnd(72, '='),
            ...this.entries
        ].join('\n');
    }
}

/* --------------------------------------------------------------------------
   Rede: fetch com timeout e erros amigáveis
   -------------------------------------------------------------------------- */
SCT.fetchJSON = async function (url, { timeout = SCT.TIMEOUT_MS, headers, asText = false } = {}) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    try {
        const res = await fetch(url, { headers, signal: ctrl.signal });
        const body = await res.text();
        let data = body;
        if (!asText) {
            try { data = body ? JSON.parse(body) : null; } catch { data = body; }
        }
        return { ok: res.ok, status: res.status, data };
    } catch (err) {
        const error = err.name === 'AbortError'
            ? 'tempo de resposta esgotado'
            : 'falha de conexão (sem internet ou serviço bloqueado pela rede)';
        return { ok: false, status: 0, data: null, error };
    } finally {
        clearTimeout(timer);
    }
};

/* DNS over HTTPS: Google como principal e Cloudflare como reserva */
const DNS_TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28 };

SCT.dns = async function (name, type) {
    const q = `name=${encodeURIComponent(name)}&type=${type}`;
    let r = await SCT.fetchJSON(`https://dns.google/resolve?${q}`);
    if (!r.ok || typeof r.data !== 'object') {
        r = await SCT.fetchJSON(`https://cloudflare-dns.com/dns-query?${q}`, {
            headers: { accept: 'application/dns-json' }
        });
    }
    if (!r.ok || !r.data || typeof r.data !== 'object') {
        return { error: r.error || `serviço DNS respondeu ${r.status}`, answers: [] };
    }
    const code = DNS_TYPES[type];
    const answers = (r.data.Answer || []).filter(a => a.type === code);
    return { status: r.data.Status, answers };
};

/* --------------------------------------------------------------------------
   Validação de entradas
   -------------------------------------------------------------------------- */
/* Aceita "https://site.com/pagina", "site.com:8080", "usuario@site.com"... e devolve só o host.
   O parser de URL também converte domínios com acento para punycode. */
SCT.sanitizeDomain = function (raw) {
    let s = String(raw || '').trim();
    if (!s) return '';
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `http://${s}`;
    try {
        return new URL(s).hostname.replace(/\.$/, '').toLowerCase();
    } catch {
        return '';
    }
};

SCT.isDomain = d => /^(?=.{1,253}$)((?!-)[a-z0-9-]{1,63}(?<!-)\.)+(xn--[a-z0-9-]{2,59}|[a-z]{2,63})$/i.test(d);

SCT.isIPv4 = ip => /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(ip);

SCT.isIPv6 = function (ip) {
    if (!ip.includes(':') || !/^[0-9a-f:.]+$/i.test(ip)) return false;
    try { new URL(`http://[${ip}]`); return true; } catch { return false; }
};

/* Classifica o IP para evitar consultas inúteis (redes internas não aparecem na internet) */
SCT.ipScope = function (ip) {
    if (SCT.isIPv4(ip)) {
        const [a, b] = ip.split('.').map(Number);
        if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
        if (a === 127) return 'loopback';
        if (a === 169 && b === 254) return 'linklocal';
        if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
        if (a === 0 || a >= 224) return 'reserved';
        return 'public';
    }
    const v6 = ip.toLowerCase();
    if (v6 === '::1') return 'loopback';
    if (/^f[cd]/.test(v6)) return 'private';
    if (/^fe[89ab]/.test(v6)) return 'linklocal';
    return 'public';
};

/* --------------------------------------------------------------------------
   Formatação (pt-BR) e privacidade
   -------------------------------------------------------------------------- */
SCT.fmtNum = n => Number(n).toLocaleString('pt-BR');

SCT.fmtDate = d => {
    const date = d instanceof Date ? d : new Date(d);
    return Number.isNaN(date.getTime()) ? '-' : date.toLocaleDateString('pt-BR');
};

SCT.age = function (d) {
    const date = d instanceof Date ? d : new Date(d);
    const days = Math.floor((Date.now() - date.getTime()) / 86400000);
    if (Number.isNaN(days)) return '';
    if (days < 1) return 'hoje';
    if (days < 31) return `há ${days} dia${days > 1 ? 's' : ''}`;
    const months = Math.floor(days / 30.44);
    if (months < 12) return `há ${months} ${months > 1 ? 'meses' : 'mês'}`;
    const years = Math.floor(days / 365.25);
    return `há ${years} ano${years > 1 ? 's' : ''}`;
};

SCT.ageInDays = d => Math.floor((Date.now() - new Date(d).getTime()) / 86400000);

SCT.truncate = (s, max = 90) => {
    const clean = String(s || '').replace(/\s+/g, ' ').trim();
    return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
};

SCT.stripHtml = html => String(html || '').replace(/<[^>]*>/g, ' ').replace(/&[a-z#0-9]+;/gi, ' ');

/* Dados de pessoa física aparecem mascarados na demonstração */
SCT.maskEmail = email => {
    const [user, host] = String(email).split('@');
    return host ? `${user[0]}•••@${host}` : '•••';
};

SCT.maskName = name => String(name)
    .split(/\s+/)
    .filter(w => w && !/^(d[aeo]s?|e)$/i.test(w))
    .map(w => `${w[0].toUpperCase()}.`)
    .join(' ');

SCT.sleep = ms => new Promise(r => setTimeout(r, ms));

SCT.register = function (name, def) {
    SCT.modules[name] = def;
};
