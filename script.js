function writeToTerminal(terminalId, message) {
    const terminal = document.getElementById(terminalId);
    if (!terminal) return;

    const newLine = document.createElement('p');
    newLine.className = 'line-log';
    const time = new Date().toLocaleTimeString();
    newLine.textContent = `> ${time} | ${message}`;
    
    terminal.appendChild(newLine);
    terminal.scrollTop = terminal.scrollHeight;
}

function updateProgress(id, val) {
    const bar = document.getElementById(id);
    if (bar) bar.value = val;
}

function downloadLog(terminalId, filename) {
    const terminal = document.getElementById(terminalId);
    const lines = Array.from(terminal.querySelectorAll('.line-log'))
                       .map(line => line.textContent)
                       .join('\n');
    
    if (!lines) return alert("Terminal vazio.");

    const blob = new Blob([`SCT LOG - ${new Date().toLocaleString()}\n\n${lines}`], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}.txt`;
    a.click();
    window.URL.revokeObjectURL(url);
}

// --- FUNÇÕES DE SCAN ---

function startInfraScan(btn) {
    const target = document.getElementById('input-infra').value;
    if (!target) return alert("Alvo vazio!");

    btn.disabled = true; // Desabilita para evitar cliques múltiplos
    const term = 'terminal-infra';
    const prog = 'progress-infra';

    updateProgress(prog, 0);
    writeToTerminal(term, `INICIANDO VARREDURA: ${target}`);

    setTimeout(() => { writeToTerminal(term, "Resolvendo DNS..."); updateProgress(prog, 30); }, 1000);
    setTimeout(() => { writeToTerminal(term, "Analisando Headers HTTP..."); updateProgress(prog, 60); }, 2500);
    setTimeout(() => { 
        writeToTerminal(term, "SCAN COMPLETO: Nenhuma vulnerabilidade crítica exposta."); 
        updateProgress(prog, 100);
        btn.disabled = false;
    }, 4500);
}

function startIdentityTrace(btn) {
    const target = document.getElementById('input-identity').value;
    if (!target) return alert("Username vazio!");

    btn.disabled = true;
    const term = 'terminal-identity';
    const prog = 'progress-identity';
    updateProgress(prog, 0);

    writeToTerminal(term, `RASTREANDO PEGADAS: ${target}`);
    
    const sites = ['Github', 'Twitter', 'LinkedIn', 'BreachData'];
    sites.forEach((site, i) => {
        setTimeout(() => {
            writeToTerminal(term, `Checando base: ${site}...`);
            updateProgress(prog, ((i + 1) / sites.length) * 100);
            if (i === sites.length - 1) btn.disabled = false;
        }, (i + 1) * 1200);
    });
}

function startDeviceAudit(btn) {
    const target = document.getElementById('input-device').value;
    if (!target) return alert("IP vazio!");

    btn.disabled = true;
    const term = 'terminal-device';
    const prog = 'progress-device';
    updateProgress(prog, 10);

    writeToTerminal(term, `AUDITANDO DISPOSITIVO: ${target}`);
    
    setTimeout(() => { writeToTerminal(term, "Porta 443 (SSL) detectada."); updateProgress(prog, 50); }, 1500);
    setTimeout(() => { 
        writeToTerminal(term, "ALERTA: Certificado auto-assinado detectado."); 
        updateProgress(prog, 100);
        btn.disabled = false;
    }, 3500);
}

// --- EFEITO VISUAL MATRIX ---

function createMatrixBackground(canvasId, parentId) {
    const canvas = document.getElementById(canvasId);
    const parent = document.getElementById(parentId);
    if (!canvas || !parent) return; 

    const ctx = canvas.getContext('2d');
    const chars = '0123456789ABCDEFHIJKLMNOPQRSTUVWXYZ';
    const fontSize = 14;
    let drops = [];

    function resize() {
        canvas.width = parent.offsetWidth;
        canvas.height = parent.offsetHeight;
        const columns = Math.floor(canvas.width / fontSize);
        drops = Array(columns).fill(1);
    }

    function draw() {
        ctx.fillStyle = 'rgba(10, 10, 10, 0.1)'; 
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00ff41';
        ctx.font = `${fontSize}px monospace`;

        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
            drops[i]++;
        }
    }

    const resizeObserver = new ResizeObserver(() => resize());
    resizeObserver.observe(parent);
    resize();
    setInterval(draw, 50);
}

document.addEventListener('DOMContentLoaded', () => {
    createMatrixBackground('canvas-infra', 'infra-tool');
    createMatrixBackground('canvas-identity', 'identity-tool');
    createMatrixBackground('canvas-device', 'device-tool');
});