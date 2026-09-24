/* ==========================================================================
   MÓDULO 03 // DEVICE AUDITOR — "O que um IP revela?"
   Geolocalização aproximada (ipwho.is / ipinfo.io) + Shodan InternetDB
   (portas, softwares e CVEs já catalogados). Diferente do TcpPortScan do
   LUCKyHAT, aqui NÃO há varredura ativa: só leitura de dados públicos.
   ========================================================================== */
'use strict';

(function () {
    /* Portas conhecidas (baseado na tabela tcp_ports do LUCKyHAT) em linguagem simples */
    const PORTS = {
        21: ['FTP', 'transferência de arquivos, sem criptografia', true],
        22: ['SSH', 'acesso remoto seguro ao servidor'],
        23: ['Telnet', 'acesso remoto SEM criptografia', true],
        25: ['SMTP', 'envio de e-mails'],
        53: ['DNS', 'tradução de nomes em IPs'],
        80: ['HTTP', 'site sem cadeado'],
        110: ['POP3', 'recebimento de e-mails'],
        111: ['RPC', 'serviço interno de sistemas Unix', true],
        123: ['NTP', 'sincronização de relógio'],
        135: ['MS-RPC', 'serviço interno do Windows', true],
        139: ['NetBIOS', 'compartilhamento de arquivos do Windows', true],
        143: ['IMAP', 'caixa de e-mail'],
        161: ['SNMP', 'monitoramento de equipamentos de rede', true],
        389: ['LDAP', 'diretório de usuários', true],
        443: ['HTTPS', 'site com cadeado'],
        445: ['SMB', 'compartilhamento de arquivos do Windows', true],
        465: ['SMTPS', 'envio de e-mails com criptografia'],
        500: ['IKE', 'VPN'],
        554: ['RTSP', 'câmeras e transmissão de vídeo', true],
        587: ['SMTP', 'envio de e-mails'],
        631: ['IPP', 'impressora na rede', true],
        853: ['DNS-over-TLS', 'DNS com criptografia'],
        993: ['IMAPS', 'caixa de e-mail com criptografia'],
        995: ['POP3S', 'recebimento de e-mails com criptografia'],
        1433: ['MSSQL', 'banco de dados', true],
        1521: ['Oracle', 'banco de dados', true],
        1723: ['PPTP', 'VPN antiga e insegura', true],
        1883: ['MQTT', 'dispositivos IoT', true],
        2049: ['NFS', 'compartilhamento de arquivos', true],
        2052: ['HTTP-alt', 'site (porta alternativa)'],
        2053: ['HTTPS-alt', 'site (porta alternativa)'],
        2082: ['cPanel', 'painel de hospedagem'],
        2083: ['cPanel', 'painel de hospedagem'],
        2086: ['WHM', 'painel de hospedagem'],
        2087: ['WHM', 'painel de hospedagem'],
        2095: ['Webmail', 'webmail do cPanel'],
        2096: ['Webmail', 'webmail do cPanel'],
        3306: ['MySQL', 'banco de dados', true],
        3389: ['RDP', 'área de trabalho remota do Windows', true],
        5060: ['SIP', 'telefonia pela internet (VoIP)'],
        5432: ['PostgreSQL', 'banco de dados', true],
        5900: ['VNC', 'controle remoto de tela', true],
        6379: ['Redis', 'banco de dados em memória', true],
        7547: ['TR-069', 'gerenciamento remoto de roteadores', true],
        8000: ['HTTP-alt', 'site / aplicação web'],
        8008: ['HTTP-alt', 'site / aplicação web'],
        8080: ['HTTP-alt', 'site / aplicação web'],
        8443: ['HTTPS-alt', 'site / aplicação web com cadeado'],
        8880: ['HTTP-alt', 'site / aplicação web'],
        8888: ['HTTP-alt', 'site / aplicação web'],
        9100: ['JetDirect', 'impressora na rede', true],
        9200: ['Elasticsearch', 'banco de dados de busca', true],
        11211: ['Memcached', 'cache de dados', true],
        27017: ['MongoDB', 'banco de dados', true]
    };

    const TAGS = {
        cloud: 'hospedado em nuvem',
        cdn: 'rede de distribuição de conteúdo (CDN)',
        vpn: 'serviço de VPN',
        proxy: 'proxy',
        tor: 'nó da rede Tor',
        'self-signed': 'certificado autoassinado',
        'eol-os': 'sistema operacional sem suporte (desatualizado)',
        'eol-product': 'software sem suporte (desatualizado)',
        starttls: 'e-mail com STARTTLS',
        database: 'banco de dados exposto',
        iot: 'dispositivo IoT',
        ics: 'sistema industrial (ICS)',
        honeypot: 'possível honeypot (armadilha para atacantes)',
        compromised: 'possivelmente comprometido',
        scanner: 'faz varreduras na internet'
    };

    const SCOPE_MSG = {
        private: 'é um IP PRIVADO: só existe dentro de uma rede local (casa, escola, empresa) e não aparece na internet.',
        loopback: 'é o endereço do PRÓPRIO computador ("localhost").',
        linklocal: 'é um endereço de link local, atribuído automaticamente quando não há rede configurada.',
        cgnat: 'pertence à faixa CGNAT: o provedor compartilha um mesmo IP público entre vários clientes.',
        reserved: 'pertence a uma faixa reservada/multicast, sem uso público.'
    };

    /* cpe:/a:apache:http_server:2.4.41 → "apache http_server 2.4.41" */
    const cpeLabel = cpe => cpe.replace(/^cpe:\/?[aho]?:?/, '').split(':').filter(Boolean).join(' ').replace(/_/g, ' ');

    async function resolveTarget(raw, term) {
        const value = String(raw || '').trim();
        if (SCT.isIPv4(value) || SCT.isIPv6(value)) return value;

        const domain = SCT.sanitizeDomain(value);
        if (!domain || !SCT.isDomain(domain)) {
            term.log('warn', `"${SCT.truncate(value, 60)}" não é um IP nem um domínio válido. Exemplos: 8.8.8.8 ou google.com`);
            return null;
        }
        term.log('info', `Resolvendo domínio ${domain} via DNS…`);
        const dns = await SCT.dns(domain, 'A');
        const ip = dns.answers[0] && dns.answers[0].data;
        if (!ip) {
            term.log('err', `Não foi possível descobrir o IP de ${domain}${dns.error ? ` (${dns.error})` : ''}.`);
            return null;
        }
        term.log('ok', `${domain} → ${ip}${dns.answers.length > 1 ? ` (+${dns.answers.length - 1} IP(s))` : ''}`);
        return ip;
    }

    async function geolocate(ip, { term, progress }) {
        term.log('head', 'GEOLOCALIZAÇÃO · onde o IP está registrado');
        let geo = null;

        const r = await SCT.fetchJSON(`https://ipwho.is/${ip}`);
        if (r.ok && r.data && r.data.success) {
            const d = r.data;
            geo = {
                country: d.country, cc: d.country_code, region: d.region, city: d.city,
                lat: d.latitude, lon: d.longitude,
                isp: d.connection && (d.connection.isp || d.connection.org),
                asn: d.connection && d.connection.asn
            };
        } else {
            const alt = await SCT.fetchJSON(`https://ipinfo.io/${ip}/json`);
            if (alt.ok && alt.data && !alt.data.bogon) {
                const d = alt.data;
                const [lat, lon] = (d.loc || ',').split(',');
                const [asn, ...org] = (d.org || '').split(' ');
                geo = { country: '', cc: d.country, region: d.region, city: d.city, lat, lon, isp: org.join(' '), asn: asn.replace(/^AS/, '') };
            }
        }
        progress(45);

        if (!geo) {
            term.log('warn', 'Serviços de geolocalização indisponíveis no momento.');
            return null;
        }

        term.log('ok', `${[geo.city, geo.region, geo.country].filter(Boolean).join(', ')}${geo.cc ? ` [${geo.cc}]` : ''}`);
        if (geo.isp) term.log('data', `Provedor / organização: ${geo.isp}${geo.asn ? ` (AS${geo.asn})` : ''}`);
        if (geo.lat && geo.lon) {
            const url = `https://www.openstreetmap.org/?mlat=${geo.lat}&mlon=${geo.lon}#map=11/${geo.lat}/${geo.lon}`;
            term.log('data', 'Mapa aproximado: ', { text: `${Number(geo.lat).toFixed(2)}, ${Number(geo.lon).toFixed(2)} (OpenStreetMap)`, href: url });
        }
        term.log('explain', 'A localização por IP é APROXIMADA: costuma indicar a cidade do provedor ou do data center — não o endereço de uma casa.');
        return geo;
    }

    async function exposure(ip, { term, progress }) {
        term.log('head', 'EXPOSIÇÃO · portas e falhas já catalogadas (Shodan InternetDB)');
        const r = await SCT.fetchJSON(`https://internetdb.shodan.io/${ip}`);
        progress(85);

        if (r.status === 404) {
            term.log('ok', 'Nenhum serviço exposto catalogado para este IP.');
            term.log('explain', 'Isso é bom: o Shodan, um "Google de dispositivos conectados", não encontrou portas abertas neste endereço.');
            return { ports: [], vulns: [] };
        }
        if (!r.ok || !r.data || typeof r.data !== 'object') {
            term.log('warn', `Base do Shodan indisponível: ${r.error || `resposta ${r.status}`}`);
            return null;
        }

        const d = r.data;
        if (d.hostnames && d.hostnames.length) {
            term.log('ok', `Nomes associados: ${d.hostnames.slice(0, 6).join(', ')}${d.hostnames.length > 6 ? '…' : ''}`);
        }

        const risky = [];
        if (d.ports && d.ports.length) {
            term.log('ok', `${d.ports.length} porta(s) aberta(s) catalogada(s):`);
            d.ports.forEach(p => {
                const info = PORTS[p];
                if (info && info[2]) risky.push(`${p}/${info[0]}`);
                term.log(info && info[2] ? 'warn' : 'data',
                    `porta ${String(p).padEnd(5)} ${info ? `${info[0]} — ${info[1]}` : 'serviço não identificado'}`);
            });
            term.log('explain', 'Portas são as "portas de entrada" de um computador: cada serviço (site, e-mail, acesso remoto) usa uma. Menos portas abertas = menos chances de ataque.');
        } else {
            term.log('ok', 'Nenhuma porta aberta catalogada.');
        }

        if (d.cpes && d.cpes.length) {
            term.log('data', `Softwares detectados: ${d.cpes.slice(0, 5).map(cpeLabel).join(', ')}`);
        }
        if (d.tags && d.tags.length) {
            term.log('data', `Características: ${d.tags.map(t => TAGS[t] || t).join(', ')}`);
        }

        const vulns = d.vulns || [];
        if (vulns.length) {
            term.log('err', `${vulns.length} vulnerabilidade(s) conhecida(s) (CVE) associada(s) a este IP:`);
            const SHOW = 8;
            for (let i = 0; i < Math.min(vulns.length, SHOW); i += 4) {
                const row = vulns.slice(i, Math.min(i + 4, SHOW)).flatMap((cve, idx) => [idx ? '  ' : '', { text: cve, href: `https://nvd.nist.gov/vuln/detail/${cve}` }]);
                term.log('data', ...row);
            }
            if (vulns.length > SHOW) {
                term.log('info', `… e mais ${vulns.length - SHOW} (lista completa no relatório).`);
                vulns.forEach(v => term.note(`  ${v}`));
            }
            term.log('explain', 'CVE é o "RG" de uma falha de segurança já conhecida. Se aparece aqui, o sistema provavelmente está desatualizado.');
        } else {
            term.log('ok', 'Nenhuma vulnerabilidade (CVE) catalogada.');
        }

        if (risky.length) {
            term.log('warn', `Serviços sensíveis expostos na internet: ${risky.join(', ')}`);
        }
        return { ports: d.ports || [], vulns };
    }

    async function audit(ip, ctx, { self = false } = {}) {
        const { term, progress } = ctx;
        term.target = ip;
        term.log('cmd', `sct audit --device ${ip}`);
        progress(20);

        const scope = SCT.ipScope(ip);
        if (scope !== 'public') {
            term.log('warn', `${ip} ${SCOPE_MSG[scope]}`);
            term.log('explain', 'Bases públicas só conhecem IPs da internet. Tente um IP público, como 8.8.8.8 (Google) ou 1.1.1.1 (Cloudflare).');
            return true;
        }
        if (self) {
            term.log('explain', 'Este é o IP público da rede que você está usando agora. Todo site que você visita consegue vê-lo!');
        }

        const geo = await geolocate(ip, ctx);
        const exp = await exposure(ip, ctx);

        term.log('head', 'RESUMO');
        term.log('ok', [
            geo ? `local aproximado: ${[geo.city, geo.cc].filter(Boolean).join('/')}` : null,
            exp ? `${exp.ports.length} porta(s) catalogada(s)` : null,
            exp ? `${exp.vulns.length} CVE(s)` : null
        ].filter(Boolean).join(' · '));
        term.log('shield', 'Nenhuma varredura foi feita no alvo: os dados já estavam em bases públicas.');
        return true;
    }

    SCT.register('device', {
        title: 'Device Auditor',
        async run(raw, ctx) {
            const ip = await resolveTarget(raw, ctx.term);
            if (!ip) return false;
            return audit(ip, ctx);
        },
        async runSelf(ctx) {
            ctx.term.log('info', 'Descobrindo o seu IP público…');
            const r = await SCT.fetchJSON('https://ipwho.is/');
            let ip = r.ok && r.data && r.data.ip;
            if (!ip) {
                const alt = await SCT.fetchJSON('https://api.ipify.org?format=json');
                ip = alt.ok && alt.data && alt.data.ip;
            }
            if (!ip) {
                ctx.term.log('err', 'Não foi possível descobrir o seu IP público agora.');
                return false;
            }
            return audit(ip, ctx, { self: true });
        }
    });
})();
