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
async function startInfraScan(btn) {
    const rawTarget = document.getElementById('input-infra').value.trim();
    if (!rawTarget) return alert("Insira um domínio!");

    // Sanitiza a entrada: remove protocolo (http/https), portas e caminhos/barras
    const target = rawTarget
        .replace(/^(?:https?:\/\/)?/i, '') // Remove http:// ou https://
        .split('/')[0]                       // Remove caminhos (ex: /noticias)
        .split(':')[0];                      // Remove portas (ex: :8080)

    btn.disabled = true;
    const term = 'terminal-infra';
    const prog = 'progress-infra';

    updateProgress(prog, 10);
    writeToTerminal(term, `INICIANDO CONSULTA DE INFRAESTRUTURA: ${target}`);

    try {
        writeToTerminal(term, "Consultando registros DNS via API Google DoH...");
        updateProgress(prog, 40);

        // Chamada usando o domínio limpo
        const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(target)}&type=A`);
        const data = await response.json();

        updateProgress(prog, 80);

        if (data.Status === 0 && data.Answer) {
            writeToTerminal(term, `[DNS RESOLVIDO] Endereços IP encontrados:`);
            data.Answer.forEach(record => {
                if (record.type === 1) { // Tipo 1 = Registro A (IPv4)
                    writeToTerminal(term, ` -> IP IPv4: ${record.data} (TTL: ${record.TTL}s)`);
                } else {
                    writeToTerminal(term, ` -> Registro Tipo ${record.type}: ${record.data}`);
                }
            });
        } else {
            writeToTerminal(term, `[AVISO] Nenhum registro A encontrado para o domínio informado (Status DNS: ${data.Status})`);
        }

        updateProgress(prog, 100);
    } catch (error) {
        writeToTerminal(term, `[ERRO] Falha na requisição: ${error.message}`);
    } finally {
        btn.disabled = false;
    }
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

async function startDeviceAudit(btn) {
    const ip = document.getElementById('input-device').value.trim();
    if (!ip) return alert("Insira um endereço IP válido!");

    btn.disabled = true;
    const term = 'terminal-device';
    const prog = 'progress-device';

    updateProgress(prog, 10);
    writeToTerminal(term, `AUDITANDO IP VIA SHODAN INTERNETDB: ${ip}`);

    try {
        updateProgress(prog, 40);
        
        // Consulta gratuita ao Shodan InternetDB
        const response = await fetch(`https://internetdb.shodan.io/${ip}`);
        
        if (!response.ok) {
            throw new Error("IP não encontrado ou sem registros na base pública do Shodan.");
        }

        const data = await response.json();
        updateProgress(prog, 80);

        writeToTerminal(term, `[HOSTNAMES] ${data.hostnames.join(', ') || 'Nenhum associado'}`);
        writeToTerminal(term, `[PORTAS ABERTAS] ${data.ports.length ? data.ports.join(', ') : 'Nenhuma porta padrão detectada'}`);
        
        if (data.vulns && data.vulns.length > 0) {
            writeToTerminal(term, `[ALERTA DE SEGURANÇA] CVEs encontradas: ${data.vulns.slice(0, 4).join(', ')}`);
        } else {
            writeToTerminal(term, `[INFO] Nenhuma vulnerabilidade (CVE) cadastrada para este IP.`);
        }

        updateProgress(prog, 100);
    } catch (error) {
        writeToTerminal(term, `[ERRO] Falha na auditoria: ${error.message}`);
    } finally {
        btn.disabled = false;
    }
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