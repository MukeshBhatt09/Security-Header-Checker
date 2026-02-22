// Expose analyze to global scope for button onclick
window.analyze = analyze;
import { marked } from "https://cdn.jsdelivr.net/npm/marked/lib/marked.esm.js";

async function analyze() {
    const url = document.getElementById("urlInput").value;
    const resultDiv = document.getElementById("result");

    resultDiv.innerHTML = "Scanning...";
    
    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        let html = "<h2>Header Analysis</h2>";

        for (const header in data.analysis) {
            const status = data.analysis[header];
            html += `<p>
                        <strong>${header}</strong>: 
                        <span class="${status === "MISSING" ? "missing" : "present"}">
                            ${status}
                        </span>
                    </p>`;
        }

        html += "<h2>AI Risk Analysis</h2>";
        html += marked.parse(data.ai_analysis);

        resultDiv.innerHTML = html;

    } catch (error) {
        resultDiv.innerHTML = "Error analyzing URL.";
    }
}


/* Professional particle-network background animation
   - Runs once (outside analyze) so it doesn't reinitialize on each scan
   - Subtle light-green nodes, connecting lines, mouse-reactive
*/
(function() {
    const canvas = document.getElementById('bgCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let DPR = window.devicePixelRatio || 1;
    let w = window.innerWidth, h = window.innerHeight, area = w * h;
    function resizeCanvas() {
        w = window.innerWidth;
        h = window.innerHeight;
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        canvas.width = Math.floor(w * DPR);
        canvas.height = Math.floor(h * DPR);
        ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
        area = w * h;
    }
    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    const mouse = { x: w / 2, y: h / 2, moved: false };
    window.addEventListener('mousemove', (e) => { mouse.x = e.clientX; mouse.y = e.clientY; mouse.moved = true; });
    window.addEventListener('mouseout', () => { mouse.moved = false; });

    function createParticles(count) {
        const arr = [];
        for (let i = 0; i < count; i++) {
            arr.push({
                x: Math.random() * w,
                y: Math.random() * h,
                vx: (Math.random() - 0.5) * 0.8,
                vy: (Math.random() - 0.5) * 0.8,
                r: 1 + Math.random() * 2.2
            });
        }
        return arr;
    }

    let particleCount = Math.max(50, Math.floor(area / 8000));
    let particles = createParticles(particleCount);

    function adjustDensity() {
        w = window.innerWidth; h = window.innerHeight; area = w * h;
        const target = Math.max(50, Math.floor(area / 8000));
        if (target > particles.length) particles = particles.concat(createParticles(target - particles.length));
        else particles.length = target;
    }
    window.addEventListener('resize', adjustDensity);

    const lineMax = 140;

    function step() {
        w = window.innerWidth; h = window.innerHeight;
        ctx.clearRect(0, 0, w, h);

        // subtle background tint
        const bg = ctx.createLinearGradient(0, 0, w, h);
        bg.addColorStop(0, 'rgba(0,0,0,0.98)');
        bg.addColorStop(1, 'rgba(0,8,0,0.98)');
        ctx.fillStyle = bg;
        ctx.fillRect(0, 0, w, h);

        // update positions
        for (let i = 0; i < particles.length; i++) {
            const p = particles[i];
            // continuous tiny jitter so motion never stalls
            p.vx += (Math.random() - 0.5) * 0.04;
            p.vy += (Math.random() - 0.5) * 0.04;

            // attraction to mouse (subtle but present even when mouse static)
            const dx = mouse.x - p.x;
            const dy = mouse.y - p.y;
            const dist = Math.hypot(dx, dy) || 1;
            const f = Math.min(0.12, 220 / (dist * dist));
            p.vx += dx * f * 0.0009;
            p.vy += dy * f * 0.0009;

            p.x += p.vx;
            p.y += p.vy;

            // gentle boundaries (wrap)
            if (p.x < -12) p.x = w + 12;
            if (p.x > w + 12) p.x = -12;
            if (p.y < -12) p.y = h + 12;
            if (p.y > h + 12) p.y = -12;

            // lighter damping so motion stays alive
            p.vx *= 0.995;
            p.vy *= 0.995;
        }

        // draw connecting lines
        ctx.beginPath();
        for (let i = 0; i < particles.length; i++) {
            const a = particles[i];
            for (let j = i + 1; j < particles.length; j++) {
                const b = particles[j];
                const dx = a.x - b.x;
                const dy = a.y - b.y;
                const d2 = dx * dx + dy * dy;
                if (d2 <= lineMax * lineMax) {
                    const alpha = 0.65 * (1 - d2 / (lineMax * lineMax));
                    ctx.strokeStyle = `rgba(150,255,160,${alpha * 0.9})`;
                    ctx.lineWidth = 0.7;
                    ctx.moveTo(a.x, a.y);
                    ctx.lineTo(b.x, b.y);
                }
            }
        }
        ctx.stroke();

        // draw particles (soft glow)
        for (let i = 0; i < particles.length; i++) {
            const p = particles[i];
            const g = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, 8);
            g.addColorStop(0, 'rgba(180,255,150,0.95)');
            g.addColorStop(0.25, 'rgba(140,255,120,0.6)');
            g.addColorStop(1, 'rgba(0,0,0,0)');
            ctx.fillStyle = g;
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r * 2.6, 0, Math.PI * 2);
            ctx.fill();
        }

        requestAnimationFrame(step);
    }

    step();
})();
