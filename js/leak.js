/* ==========================================================================
   MÓDULO 04 // LEAK CHECKER — "Sua senha já vazou?"
   Consulta a base Pwned Passwords (Have I Been Pwned) com k-anonimato:
   a senha vira um hash SHA-1 no navegador e só os 5 primeiros caracteres
   desse hash são enviados. A senha em si nunca sai deste computador.
   ========================================================================== */
'use strict';

(function () {
    const GUESSES_PER_SECOND = 1e10; // ataque offline com placas de vídeo modernas
    const COMMON = /(senha|password|passw|qwert|asdf|zxcv|abc|admin|brasil|brazil|flamengo|corinthians|palmeiras|cruzeiro|atletico|vasco|botafogo|fluminense|gremio|santos|mengo|jesus|deus|amor|iloveyou|teamo|love|mudar|trocar|12345|01234|1q2w|minas|ifsudeste)/i;
    const YEAR = /(19|20)\d{2}/;

    /* SHA-1 de reserva, caso crypto.subtle não esteja disponível (ex.: página aberta via http simples) */
    const rotl = (x, n) => (x << n) | (x >>> (32 - n));
    function sha1Fallback(str) {
        const bytes = new TextEncoder().encode(str);
        const len = bytes.length;
        const nWords = (((len + 8) >> 6) + 1) * 16;
        const words = new Array(nWords).fill(0);
        for (let i = 0; i < len; i++) words[i >> 2] |= bytes[i] << (24 - (i % 4) * 8);
        words[len >> 2] |= 0x80 << (24 - (len % 4) * 8);
        words[nWords - 1] = len * 8;

        let [h0, h1, h2, h3, h4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        const w = new Array(80);
        for (let i = 0; i < nWords; i += 16) {
            let [a, b, c, d, e] = [h0, h1, h2, h3, h4];
            for (let t = 0; t < 80; t++) {
                w[t] = t < 16 ? words[i + t] : rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
                const f = t < 20 ? (b & c) | (~b & d) : t < 40 ? b ^ c ^ d : t < 60 ? (b & c) | (b & d) | (c & d) : b ^ c ^ d;
                const k = t < 20 ? 0x5A827999 : t < 40 ? 0x6ED9EBA1 : t < 60 ? 0x8F1BBCDC : 0xCA62C1D6;
                const tmp = (rotl(a, 5) + f + e + k + w[t]) | 0;
                e = d; d = c; c = rotl(b, 30); b = a; a = tmp;
            }
            h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
        }
        return [h0, h1, h2, h3, h4].map(h => (h >>> 0).toString(16).padStart(8, '0')).join('').toUpperCase();
    }

    async function sha1(str) {
        if (window.crypto && crypto.subtle) {
            const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
            return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        }
        return sha1Fallback(str);
    }

    function humanTime(log10Seconds) {
        if (log10Seconds < 0) return 'menos de 1 segundo';
        const s = 10 ** log10Seconds;
        const units = [
            [60, 'segundo', 'segundos', 1],
            [3600, 'minuto', 'minutos', 60],
            [86400, 'hora', 'horas', 3600],
            [31557600, 'dia', 'dias', 86400],
            [31557600 * 1000, 'ano', 'anos', 31557600]
        ];
        for (const [limit, one, many, div] of units) {
            if (s < limit) {
                const n = Math.max(1, Math.round(s / div));
                return `${SCT.fmtNum(n)} ${n === 1 ? one : many}`;
            }
        }
        const years = log10Seconds - Math.log10(31557600);
        if (years > 10.14) return 'mais que a idade do universo';
        if (years >= 9) return `${SCT.fmtNum(Math.round(10 ** (years - 9)))} bilhão(ões) de anos`;
        if (years >= 6) return `${SCT.fmtNum(Math.round(10 ** (years - 6)))} milhão(ões) de anos`;
        return `${SCT.fmtNum(Math.round(10 ** (years - 3)))} mil anos`;
    }

    function strength(pw) {
        const classes = [];
        let pool = 0;
        if (/[a-z]/.test(pw)) { pool += 26; classes.push('minúsculas'); }
        if (/[A-Z]/.test(pw)) { pool += 26; classes.push('maiúsculas'); }
        if (/\d/.test(pw)) { pool += 10; classes.push('números'); }
        if (/[^a-zA-Z0-9]/.test(pw)) { pool += 33; classes.push('símbolos'); }
        const len = [...pw].length;
        const log10Seconds = len * Math.log10(pool || 1) - Math.log10(GUESSES_PER_SECOND) - Math.log10(2);
        const predictable = COMMON.test(pw) || YEAR.test(pw) || /^(.)\1+$/.test(pw);

        let level = log10Seconds < 3.56 ? 0 : log10Seconds < 7.5 ? 1 : log10Seconds < 10.5 ? 2 : 3;
        if (predictable) level = Math.min(level, 1);
        return { len, classes, log10Seconds, predictable, level };
    }

    const LEVELS = ['FRACA', 'MÉDIA', 'FORTE', 'MUITO FORTE'];

    SCT.register('leak', {
        title: 'Leak Checker',
        async run(password, { term, progress }) {
            if (!password) {
                term.log('warn', 'Digite uma senha de exemplo para testar (ex.: 123456).');
                return false;
            }
            const len = [...password].length;
            term.target = `senha de ${len} caractere(s) (oculta)`;
            term.log('cmd', `sct check --leak ${'•'.repeat(Math.min(len, 16))}`);

            term.log('head', 'K-ANONIMATO · como a consulta protege a sua senha');
            const hash = await sha1(password);
            const prefix = hash.slice(0, 5);
            const suffix = hash.slice(5);
            progress(25);
            term.log('ok', `Impressão digital (SHA-1) criada neste navegador: ${prefix}${'•'.repeat(12)}`);
            term.log('data', `Enviado para a internet: apenas "${prefix}" (5 de 40 caracteres)`);

            const url = `https://api.pwnedpasswords.com/range/${prefix}`;
            let r = await SCT.fetchJSON(url, { asText: true, headers: { 'Add-Padding': 'true' } });
            if (r.status === 0) r = await SCT.fetchJSON(url, { asText: true });
            progress(70);

            if (!r.ok) {
                term.log('err', `Não foi possível consultar a base de vazamentos: ${r.error || `resposta ${r.status}`}`);
                return false;
            }

            const rows = String(r.data).split('\n').map(l => l.trim().split(':'));
            const candidates = rows.filter(([, n]) => Number(n) > 0).length;
            const hit = rows.find(([h]) => h === suffix);
            const count = hit ? Number(hit[1]) : 0;
            term.log('ok', `Recebidos ${SCT.fmtNum(candidates)} hashes parecidos · a comparação foi feita aqui, no seu computador`);
            term.log('explain', 'É como perguntar "quais senhas começam com estas letras?" e conferir a lista em casa: o serviço nunca sabe qual era a sua.');

            term.log('head', 'RESULTADO');
            if (count > 0) {
                term.log('err', `SENHA VAZADA! Apareceu ${SCT.fmtNum(count)} vez(es) em vazamentos de dados.`);
                term.log('explain', 'Criminosos testam primeiro as senhas que já vazaram (ataque de dicionário). Se você usa esta senha em algum lugar, troque agora.');
            } else {
                term.log('ok', 'Não encontrada nos vazamentos conhecidos pelo Have I Been Pwned.');
                term.log('explain', 'Não ter vazado não significa ser forte. Veja a estimativa abaixo.');
            }

            term.log('head', 'FORÇA ESTIMADA');
            const s = strength(password);
            term.log('data', `Tamanho: ${s.len} caractere(s) · tipos: ${s.classes.join(', ') || '-'}`);
            term.log('data', `Tempo para adivinhar por força bruta: ${count > 0 ? 'instantâneo (já está nas listas de senhas vazadas)' : humanTime(s.log10Seconds)}`);
            if (s.predictable && count === 0) {
                term.log('warn', 'Contém palavra, sequência ou ano muito comum — padrões que os atacantes testam primeiro.');
            }
            const level = count > 0 ? 0 : s.level;
            term.log(level >= 2 ? 'ok' : level === 1 ? 'warn' : 'err', `Força: ${LEVELS[level]}`);
            term.log('shield', 'Dicas: use uma frase-senha (4 palavras aleatórias), uma senha diferente por site, um gerenciador de senhas e a verificação em duas etapas (2FA).');
            progress(100);
            return true;
        }
    });
})();
