/* ==========================================================================
   MÓDULO 01 // INFRASTRUCTURE SCANNER — "O que um site revela?"
   DNS completo (Google DoH), WHOIS moderno (RDAP) e subdomínios via
   Certificate Transparency (Cert Spotter). Equivale ao DnsLookup, WhoIs e
   SubdomainScan do LUCKyHAT, mas sem tocar no servidor do alvo.
   ========================================================================== */
'use strict';

(function () {
    /* Pistas de quais serviços a organização usa, a partir de MX / TXT / NS */
    const MX_PROVIDERS = [
        [/google\.com|googlemail\.com/, 'Google Workspace (Gmail)'],
        [/outlook\.com|protection\.outlook/, 'Microsoft 365 (Outlook)'],
        [/zoho\./, 'Zoho Mail'],
        [/protonmail|proton\.me/, 'Proton Mail'],
        [/icloud\.com/, 'iCloud Mail'],
        [/yahoodns/, 'Yahoo Mail'],
        [/pphosted/, 'Proofpoint'],
        [/mimecast/, 'Mimecast'],
        [/amazonses|amazonaws/, 'Amazon SES'],
        [/secureserver\.net/, 'GoDaddy'],
        [/locaweb/, 'Locaweb'],
        [/hostinger/, 'Hostinger'],
        [/kinghost/, 'KingHost'],
        [/umbler/, 'Umbler']
    ];

    const TXT_SERVICES = [
        [/^google-site-verification=/i, 'Google (Search Console / Workspace)'],
        [/^MS=ms\d+/i, 'Microsoft 365'],
        [/^facebook-domain-verification=/i, 'Meta / Facebook'],
        [/^apple-domain-verification=/i, 'Apple'],
        [/^atlassian-domain-verification=/i, 'Atlassian (Jira / Confluence)'],
        [/^docusign=/i, 'DocuSign'],
        [/^adobe-(idp-site|sign)-verification/i, 'Adobe'],
        [/^ZOOM_verify_/i, 'Zoom'],
        [/^slack-domain-verification/i, 'Slack'],
        [/^dropbox-domain-verification/i, 'Dropbox'],
        [/^openai-domain-verification/i, 'OpenAI'],
        [/^cisco-ci-domain-verification/i, 'Cisco Webex'],
        [/^stripe-verification/i, 'Stripe'],
        [/^hubspot-developer-verification|^hubspot/i, 'HubSpot'],
        [/^yandex-verification/i, 'Yandex'],
        [/^globalsign-domain-verification/i, 'GlobalSign'],
        [/^_?github-challenge/i, 'GitHub'],
        [/^canva-site-verification/i, 'Canva'],
        [/^miro-verification/i, 'Miro'],
        [/^notion-domain-verification/i, 'Notion'],
        [/^brevo-code|^Sendinblue-code/i, 'Brevo (e-mail marketing)'],
        [/include:_spf\.google\.com/i, 'Google Workspace (SPF)'],
        [/include:spf\.protection\.outlook\.com/i, 'Microsoft 365 (SPF)'],
        [/sendgrid\.net/i, 'SendGrid'],
        [/mailgun\.org/i, 'Mailgun'],
        [/amazonses\.com/i, 'Amazon SES'],
        [/mcsv\.net|mailchimp/i, 'Mailchimp']
    ];

    const NS_PROVIDERS = [
        [/cloudflare\.com/, 'Cloudflare'],
        [/awsdns/, 'Amazon Route 53'],
        [/azure-dns/, 'Microsoft Azure DNS'],
        [/googledomains|google\.com/, 'Google Cloud DNS'],
        [/dns\.br$|registro\.br/, 'Registro.br'],
        [/domaincontrol\.com/, 'GoDaddy'],
        [/hostgator/, 'HostGator'],
        [/locaweb/, 'Locaweb'],
        [/nsone\.net/, 'NS1'],
        [/ultradns/, 'UltraDNS'],
        [/akam/, 'Akamai'],
        [/digitalocean/, 'DigitalOcean'],
        [/vercel-dns/, 'Vercel'],
        [/wixdns/, 'Wix'],
        [/hostinger/, 'Hostinger']
    ];

    /* Subdomínios que costumam chamar a atenção em um reconhecimento */
    const SENSITIVE_SUB = /(^|[.-])(dev|teste?|homolog|hml|staging|stage|qa|beta|admin|painel|intranet|vpn|git|gitlab|jenkins|backup|old|legacy|sandbox)\d*([.-]|$)/i;

    const match = (list, value) => list.filter(([re]) => re.test(value)).map(([, label]) => label);
    const unique = arr => [...new Set(arr)];

    /* ---------------------------------------------------------------- DNS */
    async function scanDNS(domain, { term, progress, pivot }) {
        term.log('head', 'DNS · registros públicos do domínio');

        const [a, aaaa, mx, ns, txt, dmarc] = await Promise.all([
            SCT.dns(domain, 'A'),
            SCT.dns(domain, 'AAAA'),
            SCT.dns(domain, 'MX'),
            SCT.dns(domain, 'NS'),
            SCT.dns(domain, 'TXT'),
            SCT.dns(`_dmarc.${domain}`, 'TXT')
        ]);
        progress(35);

        if (a.error) {
            term.log('err', `Consulta DNS falhou: ${a.error}`);
            return { ok: false };
        }
        if (a.status === 3) {
            term.log('err', `O domínio "${domain}" não existe (NXDOMAIN).`);
            term.log('explain', 'Confira a grafia. Golpistas registram nomes parecidos com os oficiais (ex.: "bancco" em vez de "banco").');
            return { ok: false };
        }

        const ips = a.answers.map(r => r.data);
        if (ips.length) {
            term.log('ok', `IPv4 (A): ${ips.length} endereço(s) encontrado(s)`);
            ips.forEach(ip => term.log('data', `${ip}  (TTL ${ttlOf(a, ip)}s)  `,
                { text: '→ auditar no Módulo 03', action: () => pivot('device', ip) }));
        } else {
            term.log('warn', 'Nenhum endereço IPv4 (registro A) publicado.');
        }

        if (aaaa.answers.length) {
            term.log('ok', `IPv6 (AAAA): ${aaaa.answers.map(r => r.data).join(', ')}`);
        } else {
            term.log('info', 'IPv6 (AAAA): nenhum registro.');
        }
        term.log('explain', 'O DNS é a "agenda de contatos" da internet: traduz o nome do site para o endereço (IP) do servidor.');

        /* E-mail */
        const mxHosts = mx.answers
            .map(r => r.data.split(' '))
            .sort((x, y) => Number(x[0]) - Number(y[0]))
            .map(([, host]) => host.replace(/\.$/, ''));
        const mailProviders = unique(mxHosts.flatMap(h => match(MX_PROVIDERS, h)));
        if (mxHosts.length) {
            term.log('ok', `Servidores de e-mail (MX): ${mxHosts.slice(0, 4).join(', ')}${mxHosts.length > 4 ? '…' : ''}`);
            if (mailProviders.length) {
                term.log('data', `Provedor de e-mail identificado: ${mailProviders.join(' / ')}`);
                term.log('explain', `Só pelo DNS já dá para saber quem cuida dos e-mails deste domínio: ${mailProviders[0]}.`);
            }
        } else {
            term.log('info', 'Nenhum servidor de e-mail (MX) publicado.');
        }

        /* Servidores de nome */
        const nsHosts = ns.answers.map(r => r.data.replace(/\.$/, ''));
        if (nsHosts.length) {
            const dnsProviders = unique(nsHosts.flatMap(h => match(NS_PROVIDERS, h)));
            term.log('ok', `Servidores de nome (NS): ${nsHosts.join(', ')}`);
            if (dnsProviders.length) term.log('data', `DNS hospedado em: ${dnsProviders.join(' / ')}`);
        }

        /* TXT: verificações de serviços e SPF */
        const txts = txt.answers.map(r => r.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
        const services = unique(txts.flatMap(t => match(TXT_SERVICES, t)));
        const spf = txts.find(t => /^v=spf1/i.test(t));
        if (txts.length) {
            term.log('ok', `Registros de texto (TXT): ${txts.length}`);
            txts.forEach(t => term.note(`TXT: ${t}`));
            if (services.length) {
                term.log('data', `Serviços que o domínio usa/verificou: ${services.join(', ')}`);
                term.log('explain', 'Registros TXT revelam serviços contratados pela organização. Útil para a defesa… e também para golpistas montarem e-mails falsos convincentes.');
            }
        }

        /* Proteção contra e-mail falso */
        const dmarcRec = dmarc.answers.map(r => r.data.replace(/"/g, '')).find(t => /^v=DMARC1/i.test(t));
        const policy = dmarcRec && (dmarcRec.match(/;\s*p=(\w+)/i) || [])[1];
        term.log(spf ? 'ok' : 'warn', `SPF (quem pode enviar e-mail): ${spf ? 'configurado' : 'NÃO encontrado'}`);
        term.log(dmarcRec ? 'ok' : 'warn', `DMARC (anti-falsificação): ${dmarcRec ? `configurado (política: ${policy || '?'})` : 'NÃO encontrado'}`);
        term.log('explain', 'SPF e DMARC dificultam que criminosos enviem e-mails falsos usando este domínio (phishing).');

        return { ok: true, ips, mailProviders, services };
    }

    function ttlOf(result, ip) {
        const rec = result.answers.find(r => r.data === ip);
        return rec ? rec.TTL : '?';
    }

    /* -------------------------------------------------------------- RDAP */
    function vcardField(entity, field) {
        const items = (entity.vcardArray && entity.vcardArray[1]) || [];
        const item = items.find(i => i[0] === field);
        return item ? item[3] : '';
    }

    function flattenEntities(list, out = []) {
        (list || []).forEach(e => {
            out.push(e);
            flattenEntities(e.entities, out);
        });
        return out;
    }

    async function rdapLookup(domain) {
        let labels = domain.split('.');
        while (labels.length >= 2) {
            const d = labels.join('.');
            const r = await SCT.fetchJSON(`https://rdap.org/domain/${d}`);
            if (r.ok && r.data && r.data.objectClassName === 'domain') return { domain: d, data: r.data };
            if (r.status !== 404) return { error: r.error || `serviço RDAP respondeu ${r.status}` };
            labels = labels.slice(1);
        }
        return { error: 'registro não encontrado (este tipo de domínio pode não ter RDAP público)' };
    }

    async function scanWhois(domain, { term, progress }) {
        term.log('head', 'WHOIS / RDAP · quem registrou e quando');
        const res = await rdapLookup(domain);
        progress(60);

        if (res.error) {
            term.log('warn', `WHOIS indisponível: ${res.error}`);
            return { base: domain };
        }

        const { data } = res;
        if (res.domain !== domain) term.log('info', `Domínio registrado: ${res.domain}`);

        const events = Object.fromEntries((data.events || []).map(e => [e.eventAction, e.eventDate]));
        const created = events.registration;
        let ageDays = null;
        if (created) {
            ageDays = SCT.ageInDays(created);
            term.log('ok', `Criado em: ${SCT.fmtDate(created)} (${SCT.age(created)})`);
        }
        if (events.expiration) term.log('data', `Expira em: ${SCT.fmtDate(events.expiration)}`);
        if (events['last changed']) term.log('data', `Última alteração: ${SCT.fmtDate(events['last changed'])}`);
        if (data.status && data.status.length) term.log('data', `Status: ${data.status.join(', ')}`);

        let masked = false;
        flattenEntities(data.entities).forEach(ent => {
            const roles = ent.roles || [];
            const name = vcardField(ent, 'fn');
            if (!name) return;
            const isPerson = vcardField(ent, 'kind') === 'individual';
            const label = roles.includes('registrar') ? 'Registrador'
                : roles.includes('registrant') ? 'Titular'
                : roles.includes('technical') ? 'Contato técnico'
                : roles.includes('administrative') ? 'Contato administrativo'
                : roles.includes('abuse') ? 'Contato de abuso'
                : null;
            if (!label) return;
            if (isPerson) {
                masked = true;
                const email = vcardField(ent, 'email');
                term.log('data', `${label}: ${SCT.maskName(name)}${email ? ` · ${SCT.maskEmail(email)}` : ''} 🔒`);
            } else {
                term.log('data', `${label}: ${name}`);
            }
        });
        if (masked) {
            term.log('shield', 'Dados de pessoa física foram mascarados nesta demonstração — mas no WHOIS eles estão públicos para qualquer um!');
        }

        if (ageDays !== null && ageDays < 90) {
            term.log('warn', `ATENÇÃO: domínio criado há apenas ${ageDays} dia(s)!`);
            term.log('explain', 'Sites de golpe quase sempre usam domínios recém-criados. Desconfie de lojas e "promoções" em sites com poucos dias de vida.');
        } else if (ageDays !== null) {
            term.log('explain', `Sites de golpe costumam ter poucos dias de vida. Este domínio existe ${SCT.age(created)} — um bom sinal de legitimidade.`);
        }

        return { base: res.domain, created };
    }

    /* ------------------------------------------- Certificate Transparency */
    async function scanSubdomains(domain, base, { term, progress }) {
        term.log('head', 'SUBDOMÍNIOS · certificados HTTPS públicos (Certificate Transparency)');
        const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(base)}&include_subdomains=true&expand=dns_names`;
        const r = await SCT.fetchJSON(url, { timeout: 20000 });
        progress(90);

        if (r.status === 429) {
            term.log('warn', 'Limite gratuito de consultas de certificados atingido. Tente novamente em alguns minutos.');
            return [];
        }
        if (!r.ok || !Array.isArray(r.data)) {
            term.log('warn', `Consulta de certificados indisponível: ${r.error || `resposta ${r.status}`}`);
            return [];
        }

        const names = unique(r.data.flatMap(c => c.dns_names || [])
            .map(n => n.replace(/^\*\./, '').toLowerCase())
            .filter(n => n === base || n.endsWith(`.${base}`)))
            .sort();

        if (!names.length) {
            term.log('info', 'Nenhum certificado público recente encontrado para este domínio.');
            return [];
        }

        const SHOW = 24;
        term.log('ok', `${names.length} nome(s) encontrado(s) em ${r.data.length} certificado(s):`);
        term.log('data', names.slice(0, SHOW).join('  ·  '));
        if (names.length > SHOW) {
            term.log('info', `… e mais ${names.length - SHOW}. A lista completa vai no relatório (.txt).`);
            term.note(`Lista completa de subdomínios (${names.length}):`);
            names.forEach(n => term.note(`  ${n}`));
        }

        const sensitive = names.filter(n => SENSITIVE_SUB.test(n.slice(0, -base.length)));
        if (sensitive.length) {
            term.log('warn', `${sensitive.length} nome(s) sugerem ambientes de teste/administração (ex.: ${sensitive.slice(0, 2).join(', ')}).`);
        }
        term.log('explain', 'Todo site com cadeado (HTTPS) tem um certificado, e todo certificado é anotado em um "diário público" mundial. Por isso dá para descobrir subdomínios — inclusive de sistemas internos — sem tocar no servidor.');
        return names;
    }

    /* ------------------------------------------------------------ Execução */
    SCT.register('infra', {
        title: 'Infrastructure Scanner',
        async run(raw, ctx) {
            const { term, progress } = ctx;
            const domain = SCT.sanitizeDomain(raw);

            if (!domain || !SCT.isDomain(domain)) {
                term.log('warn', `"${SCT.truncate(raw, 60)}" não parece um domínio válido. Exemplo: ifsudestemg.edu.br`);
                return false;
            }
            term.target = domain;
            if (domain !== raw.trim().toLowerCase()) term.log('info', `Entrada limpa: "${SCT.truncate(raw, 60)}" → ${domain}`);
            term.log('cmd', `sct scan --infra ${domain}`);
            progress(10);

            const dns = await scanDNS(domain, ctx);
            if (!dns.ok) return false;

            const whois = await scanWhois(domain, ctx);
            const subs = await scanSubdomains(domain, whois.base, ctx);

            const summary = [
                `${dns.ips.length} IP(s)`,
                dns.mailProviders[0] ? `e-mail: ${dns.mailProviders[0]}` : null,
                whois.created ? `domínio criado ${SCT.age(whois.created)}` : null,
                subs.length ? `${subs.length} subdomínio(s) público(s)` : null
            ].filter(Boolean).join(' · ');
            term.log('head', 'RESUMO');
            term.log('ok', summary);
            term.log('shield', 'Nenhuma conexão foi feita diretamente com o site do alvo: tudo veio de bases públicas.');
            return true;
        }
    });
})();
