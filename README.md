# SCT // CYBER-OSINT MODULE

Plataforma educacional de **OSINT** (*Open Source Intelligence* — Inteligência de Fontes Abertas) que mostra, de forma visual e explicada para leigos, o que a internet já sabe sobre **sites, IPs, nomes de usuário e senhas**.

**Acesse:** https://honorio-samuel.github.io/OSINTsentinela/

> 🛡 Reconhecimento **100% passivo**: nenhum módulo invade, ataca, faz varredura ou login em sistemas. Todas as informações vêm de bases públicas. Uso exclusivamente educacional.

## Módulos

| # | Módulo | Pergunta | O que faz | Fontes públicas |
|---|--------|----------|-----------|-----------------|
| 01 | **Infrastructure Scanner** | O que um site revela? | DNS completo (A, AAAA, MX, NS, TXT), provedor de e-mail, SPF/DMARC, WHOIS (idade e titular do domínio) e subdomínios encontrados em certificados HTTPS | Google DNS-over-HTTPS, RDAP (rdap.org / Registro.br), Cert Spotter (Certificate Transparency) |
| 02 | **Identity Tracer** | Qual a pegada digital de um @? | Procura o mesmo nome de usuário em 14 plataformas com API pública e gera links de verificação manual para outras 13 redes (Instagram, TikTok, Duolingo…) | APIs públicas de GitHub, Minecraft (via PlayerDB), Chess.com, Lichess, Twitch, Bluesky, Mastodon, Wikipédia, Gravatar, Keybase, Dev.to, Codeberg, Hacker News e npm |
| 03 | **Device Auditor** | O que um IP revela? | Aceita IP ou domínio (ou "usar meu IP"): localização aproximada, provedor, portas abertas, softwares e CVEs já catalogados | ipwho.is / ipinfo.io, Shodan InternetDB |
| 04 | **Leak Checker** | Sua senha já vazou? | Verifica se uma senha aparece em vazamentos usando **k-anonimato** (só 5 caracteres do hash SHA-1 saem do navegador) e estima a força | Have I Been Pwned — Pwned Passwords |

## Recursos

- **💡 Explicações para leigos** em cada resultado (podem ser desligadas no topo da página).
- **Exemplos clicáveis** em todos os módulos, prontos para demonstração.
- **Pivô entre módulos**: um IP encontrado no Módulo 01 pode ser auditado no Módulo 03 com um clique.
- **Modo ampliado (⛶)** para projetor: o módulo ocupa a tela inteira com fonte maior (`Esc` para voltar).
- **Relatório .txt** e botão **Copiar** em todos os módulos.
- **Privacidade**: dados de pessoas físicas no WHOIS aparecem mascarados; senhas nunca são exibidas, registradas nem aceitas pela URL.
- **Link direto**: `?m=infra&q=ifsudestemg.edu.br` (use `&expand` para abrir ampliado). Vale para `infra`, `identity` e `device`.
- Responsivo (celular, notebook e projetor) e com efeito Matrix opcional (respeita `prefers-reduced-motion`).

## Como executar

Não há build nem servidor: é HTML, CSS e JavaScript puros.

- **Online:** GitHub Pages (link acima).
- **Local:** abra o `index.html` no navegador, ou sirva a pasta com qualquer servidor estático (ex.: `npx serve .`).

É preciso estar conectado à internet, pois os módulos consultam APIs públicas diretamente do navegador.

## Estrutura

```
index.html        Interface (4 módulos + janela "O que é OSINT?")
styles.css        Tema terminal verde, responsivo e modo ampliado
js/core.js        Terminal de saída, requisições com timeout, validações, formatação
js/infra.js       Módulo 01 — DNS, RDAP/WHOIS e Certificate Transparency
js/identity.js    Módulo 02 — busca de nome de usuário em plataformas
js/device.js      Módulo 03 — geolocalização e Shodan InternetDB
js/leak.js        Módulo 04 — Pwned Passwords com k-anonimato
js/matrix.js      Efeito visual de fundo
js/app.js         Eventos, exemplos, pivôs, relatórios e preferências
```

## Limites conhecidos

- As APIs gratuitas têm limites de uso: GitHub (60 consultas/hora por rede) e Cert Spotter podem recusar consultas em eventos com muitas pessoas na mesma rede. O sistema avisa quando isso acontece.
- Instagram, TikTok, X, Facebook e outras redes bloqueiam consultas automáticas pelo navegador; por isso aparecem como links de verificação manual.
- A geolocalização por IP é aproximada (cidade do provedor ou do data center).
- O mesmo nome de usuário em plataformas diferentes **não garante** que seja a mesma pessoa.

## Ética e legalidade

Informação pública não é "liberada para tudo". Usar dados para perseguir, expor ou enganar alguém é crime, e a LGPD protege dados pessoais mesmo quando acessíveis. Este projeto existe para **conscientização e defesa**.

## Créditos

Inspirado no [LUCKyHAT](https://github.com/RodrigoCGuedes/LUCKyHAT), ferramenta OSINT desenvolvida como projeto de extensão no **IF Sudeste MG — Campus Juiz de Fora**. Os módulos deste projeto reimplementam no navegador (sem servidor PHP) as ideias de DnsLookup, WhoIs, SubdomainScan, GeoLocalization e da tabela de portas do LUCKyHAT, trocando as varreduras ativas por consultas a bases públicas.
