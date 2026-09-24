/* ==========================================================================
   MÓDULO 02 // IDENTITY TRACER — "Qual a pegada digital de um @?"
   Procura o mesmo nome de usuário em plataformas que oferecem API pública
   (consultadas direto do navegador) e gera links de verificação manual
   para as redes que bloqueiam consultas automáticas.
   ========================================================================== */
'use strict';

(function () {
    const FOUND = 'found';
    const NOT_FOUND = 'notfound';
    const ERROR = 'error';

    const year = d => new Date(d).getFullYear();
    const since = d => `conta desde ${year(d)}`;
    const compact = parts => parts.filter(Boolean);

    /* Cada plataforma: API pública com CORS liberado + regra de nomes válidos */
    const PLATFORMS = [
        {
            name: 'GitHub',
            valid: /^[a-z0-9](?:[a-z0-9-]{0,38})$/i,
            profile: u => `https://github.com/${u}`,
            api: u => `https://api.github.com/users/${u}`,
            parse(r) {
                if (r.status === 404) return { status: NOT_FOUND };
                if (r.status === 403 || r.status === 429) return { status: ERROR, reason: 'limite de consultas do GitHub (60/hora por rede)' };
                if (!r.ok) return null;
                const d = r.data;
                return {
                    status: FOUND,
                    details: compact([
                        d.name && `nome: ${d.name}`,
                        d.location && `local: ${d.location}`,
                        d.company && `empresa: ${d.company}`,
                        d.bio && `bio: "${SCT.truncate(d.bio, 70)}"`,
                        `${SCT.fmtNum(d.public_repos)} repositório(s) · ${SCT.fmtNum(d.followers)} seguidor(es) · ${since(d.created_at)}`
                    ])
                };
            }
        },
        {
            name: 'Duolingo',
            valid: /^[a-z0-9_.-]{1,30}$/i,
            profile: u => `https://www.duolingo.com/profile/${u}`,
            api: u => `https://www.duolingo.com/2017-06-30/users?username=${encodeURIComponent(u)}&fields=users%7Busername,name,streak,creationDate,totalXp%7D`,
            parse(r) {
                if (!r.ok) return null;
                const user = r.data && r.data.users && r.data.users[0];
                if (!user) return { status: NOT_FOUND };
                return {
                    status: FOUND,
                    details: compact([
                        user.name && `nome: ${user.name}`,
                        `ofensiva: ${SCT.fmtNum(user.streak || 0)} dia(s) · ${SCT.fmtNum(user.totalXp || 0)} XP`,
                        user.creationDate && since(user.creationDate * 1000)
                    ])
                };
            }
        },
        {
            name: 'Chess.com',
            valid: /^[a-z0-9_-]{3,25}$/i,
            profile: u => `https://www.chess.com/member/${u}`,
            api: u => `https://api.chess.com/pub/player/${u.toLowerCase()}`,
            parse(r) {
                if (r.status === 404 || r.status === 410) return { status: NOT_FOUND };
                if (!r.ok) return null;
                const d = r.data;
                const country = d.country ? d.country.split('/').pop() : '';
                return {
                    status: FOUND,
                    details: compact([
                        d.name && `nome: ${d.name}`,
                        (d.location || country) && `local: ${compact([d.location, country]).join(' · ')}`,
                        d.joined && since(d.joined * 1000)
                    ])
                };
            }
        },
        {
            name: 'Lichess',
            valid: /^[a-z0-9][a-z0-9_-]{1,29}$/i,
            profile: u => `https://lichess.org/@/${u}`,
            api: u => `https://lichess.org/api/user/${u}`,
            parse(r) {
                if (r.status === 404) return { status: NOT_FOUND };
                if (!r.ok) return null;
                const d = r.data;
                if (d.disabled || d.closed) return { status: NOT_FOUND };
                return {
                    status: FOUND,
                    details: compact([
                        d.profile && d.profile.location && `local: ${d.profile.location}`,
                        d.count && `${SCT.fmtNum(d.count.all)} partida(s)`,
                        d.createdAt && since(d.createdAt)
                    ])
                };
            }
        },
        {
            name: 'Twitch',
            valid: /^[a-z0-9_]{4,25}$/i,
            profile: u => `https://www.twitch.tv/${u}`,
            api: u => `https://decapi.me/twitch/id/${u}`,
            asText: true,
            parse(r) {
                if (r.ok && /^\d+$/.test(String(r.data).trim())) return { status: FOUND, details: [] };
                if (r.status === 400 || r.status === 404 || r.ok) return { status: NOT_FOUND };
                return null;
            }
        },
        {
            name: 'Bluesky',
            valid: /^[a-z0-9-]{3,18}$/i,
            profile: u => `https://bsky.app/profile/${u.toLowerCase()}.bsky.social`,
            api: u => `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${u.toLowerCase()}.bsky.social`,
            parse(r) {
                if (r.status === 400 || r.status === 404) return { status: NOT_FOUND };
                if (!r.ok) return null;
                const d = r.data;
                return {
                    status: FOUND,
                    details: compact([
                        d.displayName && `nome: ${d.displayName}`,
                        d.description && `bio: "${SCT.truncate(d.description, 70)}"`,
                        `${SCT.fmtNum(d.followersCount || 0)} seguidor(es)${d.createdAt ? ` · ${since(d.createdAt)}` : ''}`
                    ])
                };
            }
        },
        {
            name: 'Mastodon',
            valid: /^[a-z0-9_]{1,30}$/i,
            profile: u => `https://mastodon.social/@${u}`,
            api: u => `https://mastodon.social/api/v1/accounts/lookup?acct=${u}`,
            parse(r) {
                if (r.status === 404) return { status: NOT_FOUND };
                if (!r.ok) return null;
                const d = r.data;
                const bio = SCT.stripHtml(d.note);
                return {
                    status: FOUND,
                    details: compact([
                        d.display_name && `nome: ${d.display_name}`,
                        bio.trim() && `bio: "${SCT.truncate(bio, 70)}"`,
                        `${SCT.fmtNum(d.followers_count || 0)} seguidor(es) · ${since(d.created_at)}`
                    ])
                };
            }
        },
        {
            name: 'Wikipédia',
            valid: /^[^#<>[\]|{}/@:]{1,85}$/,
            profile: u => `https://pt.wikipedia.org/wiki/Usuário:${encodeURIComponent(u)}`,
            api: u => `https://pt.wikipedia.org/w/api.php?action=query&list=users&ususers=${encodeURIComponent(u)}&usprop=editcount%7Cregistration&format=json&origin=*`,
            parse(r) {
                if (!r.ok) return null;
                const user = r.data && r.data.query && r.data.query.users && r.data.query.users[0];
                if (!user || 'missing' in user || 'invalid' in user) return { status: NOT_FOUND };
                return {
                    status: FOUND,
                    details: compact([
                        `${SCT.fmtNum(user.editcount || 0)} edição(ões)`,
                        user.registration && since(user.registration)
                    ])
                };
            }
        },
        {
            name: 'Gravatar',
            valid: /^[a-z0-9_.-]{1,40}$/i,
            profile: u => `https://gravatar.com/${u}`,
            api: u => `https://en.gravatar.com/${u}.json`,
            parse(r) {
                if (r.status === 404) return { status: NOT_FOUND };
                if (!r.ok) return null;
                const d = r.data && r.data.entry && r.data.entry[0];
                if (!d) return { status: NOT_FOUND };
                const accounts = (d.accounts || []).map(a => a.shortname || a.domain).filter(Boolean);
                return {
                    status: FOUND,
                    details: compact([
                        d.displayName && `nome: ${d.displayName}`,
                        d.currentLocation && `local: ${d.currentLocation}`,
                        accounts.length && `contas vinculadas: ${accounts.join(', ')}`
                    ])
                };
            }
        },
        {
            name: 'Keybase',
            valid: /^[a-z0-9_]{2,16}$/i,
            profile: u => `https://keybase.io/${u}`,
            api: u => `https://keybase.io/_/api/1.0/user/lookup.json?usernames=${u}&fields=profile,proofs_summary`,
            parse(r) {
                if (!r.ok) return null;
                const d = r.data && r.data.them && r.data.them[0];
                if (!d) return { status: NOT_FOUND };
                const proofs = ((d.proofs_summary && d.proofs_summary.all) || []).map(p => p.proof_type);
                return {
                    status: FOUND,
                    details: compact([
                        d.profile && d.profile.full_name && `nome: ${d.profile.full_name}`,
                        d.profile && d.profile.location && `local: ${d.profile.location}`,
                        proofs.length && `contas vinculadas: ${[...new Set(proofs)].join(', ')}`
                    ])
                };
            }
        },
        {
            name: 'Dev.to',
            valid: /^[a-z0-9_]{1,30}$/i,
            profile: u => `https://dev.to/${u}`,
            api: u => `https://dev.to/api/users/by_username?url=${u}`,
            parse(r) {
                if (r.status === 404) return { status: NOT_FOUND };
                if (!r.ok) return null;
                const d = r.data;
                return {
                    status: FOUND,
                    details: compact([
                        d.name && `nome: ${d.name}`,
                        d.location && `local: ${d.location}`,
                        d.joined_at && `entrou em: ${d.joined_at}`
                    ])
                };
            }
        },
        {
            name: 'Codeberg',
            valid: /^[a-z0-9_.-]{1,40}$/i,
            profile: u => `https://codeberg.org/${u}`,
            api: u => `https://codeberg.org/api/v1/users/${u}`,
            parse(r) {
                if (r.status === 404) return { status: NOT_FOUND };
                if (!r.ok) return null;
                const d = r.data;
                return {
                    status: FOUND,
                    details: compact([
                        d.full_name && `nome: ${d.full_name}`,
                        d.location && `local: ${d.location}`,
                        d.created && since(d.created)
                    ])
                };
            }
        },
        {
            name: 'Hacker News',
            valid: /^[a-z0-9_-]{2,15}$/i,
            profile: u => `https://news.ycombinator.com/user?id=${u}`,
            api: u => `https://hacker-news.firebaseio.com/v0/user/${u}.json`,
            parse(r) {
                if (!r.ok) return null;
                if (!r.data) return { status: NOT_FOUND };
                return {
                    status: FOUND,
                    details: [`karma: ${SCT.fmtNum(r.data.karma || 0)} · ${since(r.data.created * 1000)}`]
                };
            }
        },
        {
            name: 'npm',
            valid: /^[a-z0-9_.-]{1,214}$/i,
            profile: u => `https://www.npmjs.com/~${u.toLowerCase()}`,
            api: u => `https://registry.npmjs.org/-/v1/search?text=maintainer:${encodeURIComponent(u.toLowerCase())}&size=1`,
            parse(r) {
                if (!r.ok) return null;
                const total = r.data && r.data.total;
                if (!total) return { status: NOT_FOUND };
                return { status: FOUND, details: [`${SCT.fmtNum(total)} pacote(s) publicado(s)`] };
            }
        }
    ];

    /* Redes que bloqueiam consultas automáticas pelo navegador: verificação manual */
    const MANUAL = [
        ['Instagram', u => `https://www.instagram.com/${u}/`],
        ['TikTok', u => `https://www.tiktok.com/@${u}`],
        ['X / Twitter', u => `https://x.com/${u}`],
        ['YouTube', u => `https://www.youtube.com/@${u}`],
        ['Facebook', u => `https://www.facebook.com/${u}`],
        ['Threads', u => `https://www.threads.net/@${u}`],
        ['Reddit', u => `https://www.reddit.com/user/${u}`],
        ['Roblox', u => `https://www.roblox.com/search/users?keyword=${u}`],
        ['Steam', u => `https://steamcommunity.com/id/${u}`],
        ['Pinterest', u => `https://www.pinterest.com/${u}/`],
        ['Scratch', u => `https://scratch.mit.edu/users/${u}/`],
        ['Telegram', u => `https://t.me/${u}`]
    ];

    async function check(platform, username) {
        if (!platform.valid.test(username)) return { status: NOT_FOUND, reason: 'nome inválido nesta plataforma' };
        const r = await SCT.fetchJSON(platform.api(username), { timeout: 10000, asText: platform.asText });
        if (r.status === 0) return { status: ERROR, reason: r.error };
        try {
            const parsed = platform.parse(r);
            return parsed || { status: ERROR, reason: `resposta inesperada (${r.status})` };
        } catch {
            return { status: ERROR, reason: 'resposta em formato inesperado' };
        }
    }

    SCT.register('identity', {
        title: 'Identity Tracer',
        async run(raw, { term, progress }) {
            const username = String(raw || '').trim().replace(/^@+/, '');
            if (!username || !/^[\p{L}\p{N}_.-]{1,40}$/u.test(username)) {
                term.log('warn', 'Digite um nome de usuário (sem espaços), por exemplo: torvalds');
                return false;
            }
            term.target = `@${username}`;
            term.log('cmd', `sct trace --identity @${username}`);
            term.log('info', `Consultando ${PLATFORMS.length} plataformas com API pública ao mesmo tempo…`);
            progress(8);

            let done = 0;
            const found = [];
            let errors = 0;

            await Promise.all(PLATFORMS.map(async platform => {
                const res = await check(platform, username);
                done += 1;
                progress(8 + Math.round((done / PLATFORMS.length) * 80));

                const url = platform.profile(username);
                if (res.status === FOUND) {
                    found.push(platform.name);
                    term.log('ok', `ENCONTRADO · ${platform.name} → `, { text: url.replace(/^https:\/\/(www\.)?/, ''), href: url });
                    (res.details || []).forEach(d => term.log('data', d));
                } else if (res.status === ERROR) {
                    errors += 1;
                    term.log('warn', `${platform.name}: não foi possível verificar — ${res.reason}`);
                } else {
                    term.log('info', `✖ ${platform.name}: não encontrado`);
                }
            }));

            term.log('head', 'RESUMO');
            const checked = PLATFORMS.length - errors;
            if (found.length) {
                term.log('ok', `@${username} existe em ${found.length} de ${checked} plataformas verificadas: ${found.join(', ')}`);
            } else {
                term.log('ok', `@${username} não apareceu em nenhuma das ${checked} plataformas verificadas.`);
            }

            term.log('head', 'VERIFICAÇÃO MANUAL · redes que bloqueiam consultas automáticas');
            for (let i = 0; i < MANUAL.length; i += 4) {
                const row = MANUAL.slice(i, i + 4).flatMap(([name, url], idx) => [idx ? '  ·  ' : '', { text: name, href: url(username) }]);
                term.log('data', ...row);
            }

            term.log('explain', 'Quem usa o mesmo @ em todo lugar facilita que qualquer pessoa junte as peças: nome, cidade, foto, escola, rotina, gostos…');
            term.log('warn', 'Mesmo @ não significa mesma pessoa! Um bom investigador sempre confirma antes de concluir (falso positivo).');
            term.log('shield', 'Proteja-se: revise o que está público nos seus perfis e evite expor escola, endereço e rotina.');
            progress(100);
            return true;
        }
    });
})();
