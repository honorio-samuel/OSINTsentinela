/* ==========================================================================
   Efeito visual "Matrix" — um único canvas no fundo da página.
   Usa requestAnimationFrame (pausa sozinho em abas escondidas) e pode ser
   desligado pelo usuário ou automaticamente com prefers-reduced-motion.
   ========================================================================== */
'use strict';

(function () {
    const canvas = document.getElementById('matrix-bg');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const CHARS = '0123456789ABCDEFHIJKLMNOPQRSTUVWXYZ';
    const SIZE = 16;
    const FRAME_MS = 60;
    let drops = [];
    let raf = null;
    let last = 0;

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        drops = Array.from({ length: Math.ceil(canvas.width / SIZE) }, () => Math.floor(Math.random() * -80));
        ctx.fillStyle = '#0d0d0d';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
    }

    function draw(t) {
        raf = requestAnimationFrame(draw);
        if (t - last < FRAME_MS) return;
        last = t;

        ctx.fillStyle = 'rgba(13, 13, 13, 0.12)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00ff41';
        ctx.font = `${SIZE}px monospace`;

        for (let i = 0; i < drops.length; i++) {
            const y = drops[i];
            if (y >= 0) ctx.fillText(CHARS[(Math.random() * CHARS.length) | 0], i * SIZE, y * SIZE);
            drops[i] = (y * SIZE > canvas.height && Math.random() > 0.975) ? 0 : y + 1;
        }
    }

    SCT.matrix = {
        start() {
            if (raf) return;
            canvas.hidden = false;
            resize();
            raf = requestAnimationFrame(draw);
        },
        stop() {
            cancelAnimationFrame(raf);
            raf = null;
            canvas.hidden = true;
        }
    };

    window.addEventListener('resize', () => { if (raf) resize(); });
})();
