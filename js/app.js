/* ==========================================================================
   Interface: liga formulários, exemplos, pivôs entre módulos, relatórios,
   modo ampliado para projetor e preferências do usuário.
   ========================================================================== */
'use strict';

(function () {
    const MODULES = ['infra', 'identity', 'device', 'leak'];
    const IDLE = {
        infra: 'Aguardando domínio… clique em um exemplo ou digite o endereço de um site.',
        identity: 'Aguardando @… digite um nome de usuário para rastrear.',
        device: 'Aguardando IP ou domínio… ou clique em "USAR MEU IP".',
        leak: 'Aguardando senha de exemplo… ela nunca sai deste computador.'
    };

    const cards = {};
    const terminals = {};
    let queries = 0;

    /* ---------------------------------------------------------- Preferências */
    const prefs = {
        get(key, fallback) {
            try {
                const v = localStorage.getItem(`sct.${key}`);
                return v === null ? fallback : v === '1';
            } catch { return fallback; }
        },
        set(key, value) {
            try { localStorage.setItem(`sct.${key}`, value ? '1' : '0'); } catch { /* modo privado */ }
        }
    };

    function updateStatus() {
        const el = document.getElementById('system-status-text');
        if (!el) return;
        el.textContent = `SISTEMA ATIVO · ${MODULES.length} MÓDULOS ONLINE · ${queries} CONSULTA${queries === 1 ? '' : 'S'} NESTA SESSÃO`;
    }

    /* -------------------------------------------------------------- Execução */
    async function execute(name, value, { self = false } = {}) {
        const card = cards[name];
        if (card.classList.contains('busy')) return;

        const term = terminals[name];
        const bar = card.querySelector('progress');
        const input = card.querySelector('.tool-controls input');
        const buttons = card.querySelectorAll('.tool-controls button');
        const submit = card.querySelector('.tool-controls button[type="submit"]');
        const label = submit.textContent;

        card.classList.add('busy');
        buttons.forEach(b => { b.disabled = true; });
        submit.textContent = 'PROCESSANDO…';
        term.clear();
        term.target = '';
        bar.value = 3;

        const ctx = { term, progress: v => { bar.value = v; }, pivot };
        let ok = false;
        try {
            const mod = SCT.modules[name];
            ok = self ? await mod.runSelf(ctx) : await mod.run(value, ctx);
        } catch (err) {
            console.error(err);
            term.log('err', `Erro inesperado: ${err.message}`);
        } finally {
            card.classList.remove('busy');
            buttons.forEach(b => { b.disabled = false; });
            submit.textContent = label;
            bar.value = ok ? 100 : 0;
            if (name === 'leak') input.value = '';
            if (!ok) {
                input.classList.remove('shake');
                void input.offsetWidth;
                input.classList.add('shake');
            }
            queries += 1;
            updateStatus();
        }
    }

    /* Pivô: usa o resultado de um módulo como entrada de outro (fluxo real de investigação) */
    function pivot(name, value) {
        const card = cards[name];
        card.querySelector('.tool-controls input').value = value;
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        card.classList.remove('flash');
        void card.offsetWidth;
        card.classList.add('flash');
        execute(name, value);
    }

    /* ------------------------------------------------------------ Relatórios */
    function download(name) {
        const term = terminals[name];
        if (!term.entries.length) return flashButton(name, '[data-export]', 'NADA PARA SALVAR');
        const blob = new Blob([term.toText(SCT.modules[name].title)], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const slug = (term.target || 'relatorio').replace(/[^a-z0-9.-]+/gi, '_').slice(0, 40);
        a.href = url;
        a.download = `sct_${name}_${slug}_${new Date().toISOString().slice(0, 10)}.txt`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    async function copy(name) {
        const term = terminals[name];
        if (!term.entries.length) return flashButton(name, '[data-copy]', 'NADA PARA COPIAR');
        try {
            await navigator.clipboard.writeText(term.toText(SCT.modules[name].title));
            flashButton(name, '[data-copy]', 'COPIADO ✔');
        } catch {
            flashButton(name, '[data-copy]', 'SEM PERMISSÃO');
        }
    }

    function flashButton(name, selector, text) {
        const btn = cards[name].querySelector(selector);
        const original = btn.dataset.label || btn.textContent;
        btn.dataset.label = original;
        btn.textContent = text;
        setTimeout(() => { btn.textContent = original; }, 1600);
    }

    /* ------------------------------------------------------ Modo projetor */
    function toggleExpand(name, force) {
        const card = cards[name];
        const expand = force ?? !card.classList.contains('expanded');
        MODULES.forEach(m => {
            cards[m].classList.remove('expanded');
            cards[m].querySelector('[data-expand]').textContent = '⛶ AMPLIAR';
        });
        document.body.classList.toggle('has-expanded', expand);
        if (expand) {
            card.classList.add('expanded');
            card.querySelector('[data-expand]').textContent = '✕ REDUZIR';
            window.scrollTo({ top: card.offsetTop - 90, behavior: 'smooth' });
            card.querySelector('.tool-controls input').focus({ preventScroll: true });
        }
    }

    /* ------------------------------------------------------------- Início */
    document.addEventListener('DOMContentLoaded', () => {
        MODULES.forEach(name => {
            const card = document.querySelector(`[data-module="${name}"]`);
            cards[name] = card;
            terminals[name] = new Terminal(card.querySelector('.terminal-box'));
            terminals[name].idle(IDLE[name]);

            card.querySelector('.tool-controls').addEventListener('submit', e => {
                e.preventDefault();
                execute(name, card.querySelector('.tool-controls input').value);
            });

            card.querySelectorAll('.chip').forEach(chip => chip.addEventListener('click', () => {
                card.querySelector('.tool-controls input').value = chip.dataset.value;
                execute(name, chip.dataset.value);
            }));

            card.querySelector('[data-export]').addEventListener('click', () => download(name));
            card.querySelector('[data-copy]').addEventListener('click', () => copy(name));
            card.querySelector('[data-clear]').addEventListener('click', () => {
                terminals[name].idle(IDLE[name]);
                card.querySelector('progress').value = 0;
            });
            card.querySelector('[data-expand]').addEventListener('click', () => toggleExpand(name));
        });

        document.getElementById('btn-self-ip').addEventListener('click', () => execute('device', '', { self: true }));

        const pw = document.getElementById('input-leak');
        const reveal = document.getElementById('btn-reveal');
        reveal.addEventListener('click', () => {
            const show = pw.type === 'password';
            pw.type = show ? 'text' : 'password';
            reveal.setAttribute('aria-pressed', String(show));
            reveal.textContent = show ? 'OCULTAR' : 'MOSTRAR';
        });

        /* Explicações para leigos */
        const explain = document.getElementById('toggle-explain');
        explain.checked = prefs.get('explain', true);
        document.body.classList.toggle('hide-explain', !explain.checked);
        explain.addEventListener('change', () => {
            document.body.classList.toggle('hide-explain', !explain.checked);
            prefs.set('explain', explain.checked);
        });

        /* Efeito Matrix */
        const matrix = document.getElementById('toggle-matrix');
        const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        matrix.checked = prefs.get('matrix', !reduced);
        if (matrix.checked) SCT.matrix.start(); else SCT.matrix.stop();
        matrix.addEventListener('change', () => {
            if (matrix.checked) SCT.matrix.start(); else SCT.matrix.stop();
            prefs.set('matrix', matrix.checked);
        });

        /* Janela "O que é OSINT?" */
        const dialog = document.getElementById('about-dialog');
        document.getElementById('btn-about').addEventListener('click', () => dialog.showModal());
        dialog.querySelector('[data-close]').addEventListener('click', () => dialog.close());
        dialog.addEventListener('click', e => { if (e.target === dialog) dialog.close(); });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && document.body.classList.contains('has-expanded') && !dialog.open) {
                MODULES.forEach(m => cards[m].classList.contains('expanded') && toggleExpand(m, false));
            }
        });

        updateStatus();

        /* Link direto: ?m=infra&q=ifsudestemg.edu.br (senhas nunca são aceitas pela URL) */
        const params = new URLSearchParams(location.search);
        const m = params.get('m');
        const q = params.get('q');
        if (m && q && m !== 'leak' && cards[m]) {
            cards[m].querySelector('.tool-controls input').value = q;
            if (params.has('expand')) toggleExpand(m, true);
            execute(m, q);
        }
    });
})();
