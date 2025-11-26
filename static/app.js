// Utilidad para pausar la ejecución (Rate Limiting)
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms * 1000));

// Gestión del estado global
let isProcessing = false;

// Gestión del estado global
let totalSesionCounter = 0; // <--- NUEVA VARIABLE

async function consultarVirusTotal(ioc, apiKey) {
    try {
        const response = await fetch('/consultar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ioc: ioc, apiKey: apiKey })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `Error ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        return { error: error.message };
    }
}

function filtrarIOCs(texto) {
    const lines = texto.split('\n');
    // Sets para evitar duplicados automáticamente
    const hashes = new Set();
    const urls = new Set();
    const domains = new Set();
    const ips = new Set();

    const hashPattern = /\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g;
    const urlPattern = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/g;
    const domainPattern = /\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b/g;
    const ipv4Pattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

    // Escanear todo el texto, no solo línea por línea (mejor para textos grandes)
    const allText = texto;

    let match;
    while ((match = hashPattern.exec(allText)) !== null) hashes.add(match[0]);
    while ((match = urlPattern.exec(allText)) !== null) urls.add(match[0]);
    while ((match = ipv4Pattern.exec(allText)) !== null) ips.add(match[0]);
    
    // Los dominios son tricky porque las URLs contienen dominios. 
    // Si ya está en URL, no lo añadimos a dominios para no duplicar escaneo
    while ((match = domainPattern.exec(allText)) !== null) {
        if (!allText.includes(match[0] + "/")) { // Simple check heurístico
            domains.add(match[0]);
        }
    }

    return [...hashes, ...urls, ...domains, ...ips];
}

// --- MODIFICACIÓN 1: Añadimos data-sort para poder ordenar correctamente ---
function agregarFilaTabla(ioc, tipo, detecciones, total, error = null, link = '#') {
    const tbody = document.querySelector('#results-table tbody');
    const row = document.createElement('tr');
    
    let estadoClass = '';
    let estadoIcon = '';
    let textoDeteccion = '';
    let sortValueEstado = 0; // 0: Error, 1: Clean, 2: Suspicious, 3: Malicious

    if (error) {
        estadoClass = 'status-error';
        estadoIcon = '<i class="fa-solid fa-circle-exclamation"></i> Error';
        textoDeteccion = error;
        sortValueEstado = 0;
    } else {
        textoDeteccion = `${detecciones} / ${total}`;
        if (detecciones === 0) {
            estadoClass = 'status-clean';
            estadoIcon = '<i class="fa-solid fa-check-circle"></i> Limpio';
            sortValueEstado = 1;
        } else if (detecciones < 3) {
            estadoClass = 'status-warning';
            estadoIcon = '<i class="fa-solid fa-triangle-exclamation"></i> Sospechoso';
            sortValueEstado = 2;
        } else {
            estadoClass = 'status-malicious';
            estadoIcon = '<i class="fa-solid fa-skull"></i> Malicioso';
            sortValueEstado = 3;
        }
    }

    // Nota los atributos 'data-sort' en los TDs. Son clave para ordenar.
    row.innerHTML = `
        <td class="col-ioc" title="${ioc}" data-sort="${ioc.toLowerCase()}">${ioc}</td>
        <td data-sort="${tipo || 'z'}">${tipo || 'Desc.'}</td>
        <td data-sort="${detecciones}">${textoDeteccion}</td>
        <td data-sort="${sortValueEstado}"><span class="badge ${estadoClass}">${estadoIcon}</span></td>
        <td>${!error ? `<a href="${link}" target="_blank" class="link-vt">Ver Reporte</a>` : '-'}</td>
    `;
    tbody.appendChild(row);
}

// --- MODIFICACIÓN 2: Lógica corregida para los enlaces de VirusTotal ---
async function iniciarProceso() {
    if (isProcessing) return;
    
    // 1. Obtener valores de la UI
    const apiKey = document.getElementById('api-key').value.trim();
    const texto = document.getElementById('ioc-input').value.trim();
    const delay = parseFloat(document.getElementById('delay-input').value) || 0;
    const modo = document.querySelector('input[name="modo"]:checked').value;
    
    // 2. Validaciones básicas
    if (!apiKey) {
        alert("¡Necesitas una API Key de VirusTotal!");
        return;
    }
    if (!texto) return;

    // 3. Preparar UI para el inicio
    isProcessing = true;
    document.getElementById('btn-check').disabled = true;
    document.querySelector('#results-table tbody').innerHTML = '';
    document.getElementById('progress-container').style.display = 'block';
    document.getElementById('stats-summary').style.display = 'none';

    // 4. Procesar la lista de IOCs según el modo
    let iocs = [];
    if (modo === "Filtrado") {
        iocs = filtrarIOCs(texto);
    } else {
        iocs = texto.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    }

    let maliciousCount = 0;

    // 5. Bucle principal
    for (const [index, ioc] of iocs.entries()) {
        // Actualizar barra de progreso
        const percent = ((index + 1) / iocs.length) * 100;
        document.getElementById('progress-fill').style.width = `${percent}%`;
        document.getElementById('status-text').textContent = `Analizando ${index + 1} de ${iocs.length}: ${ioc}`;

        // --- NUEVO: Actualizar contador de sesión ---
        // Sumamos 1 a la variable global y actualizamos el HTML
        if (typeof totalSesionCounter !== 'undefined') {
            totalSesionCounter++;
            const sessionElem = document.getElementById('session-total');
            if (sessionElem) sessionElem.innerText = totalSesionCounter;
        }

        // Consultar Backend
        const resultado = await consultarVirusTotal(ioc, apiKey);

        if (resultado.error) {
            agregarFilaTabla(ioc, 'Unknown', 0, 0, resultado.error);
        } else if (resultado.data && resultado.data.length > 0) {
            const data = resultado.data[0]; 
            const attr = data.attributes;
            const stats = attr.last_analysis_stats;
            const malicious = stats.malicious || 0;
            const total = (stats.malicious + stats.harmless + stats.suspicious + stats.undetected) || 0;
            const type = data.type; 
            const id = data.id;     
            
            // --- GENERACIÓN DE ENLACES CORRECTA ---
            let link = `https://www.virustotal.com/gui/search/${ioc}`; // Fallback por defecto

            if (type === 'url') {
                link = `https://www.virustotal.com/gui/url/${id}`; 
            } else if (type === 'domain') {
                link = `https://www.virustotal.com/gui/domain/${id}`;
            } else if (type === 'ip_address') {
                link = `https://www.virustotal.com/gui/ip-address/${id}`;
            } else if (type === 'file') {
                link = `https://www.virustotal.com/gui/file/${id}`;
            }

            if (malicious > 0) maliciousCount++;

            agregarFilaTabla(ioc, type, malicious, total, null, link);
        } else {
            // Caso: No encontrado en VT
            agregarFilaTabla(ioc, '-', 0, 0, 'No encontrado en VT');
        }

        // Aplicar Delay si no es el último IOC
        if (index < iocs.length - 1 && delay > 0) {
            await sleep(delay);
        }
    }

    // 6. Finalizar proceso
    isProcessing = false;
    document.getElementById('btn-check').disabled = false;
    document.getElementById('status-text').textContent = `Completado. ${maliciousCount} maliciosos encontrados.`;
    document.getElementById('stats-summary').style.display = 'block';
    document.getElementById('summary-text').textContent = `Total: ${iocs.length} | Maliciosos: ${maliciousCount}`;
}

// --- MODIFICACIÓN 3: Nueva función para ordenar la tabla ---
let currentSortColumn = -1;
let currentSortDir = 'asc';

function ordenarTabla(n) {
    const table = document.getElementById("results-table");
    const tbody = table.querySelector("tbody");
    const rows = Array.from(tbody.rows);
    
    // Resetear iconos de otros headers si quisieras (opcional)
    
    // Invertir dirección si hacemos click en la misma columna
    if (currentSortColumn === n) {
        currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
    } else {
        currentSortColumn = n;
        currentSortDir = 'asc'; // Reset a ascendente en nueva columna
    }

    rows.sort((rowA, rowB) => {
        // Obtenemos el valor 'data-sort' si existe, si no el texto interno
        let cellA = rowA.cells[n].getAttribute('data-sort') || rowA.cells[n].innerText.toLowerCase();
        let cellB = rowB.cells[n].getAttribute('data-sort') || rowB.cells[n].innerText.toLowerCase();

        // Detectar si son números para ordenar matemáticamente
        const isNum = !isNaN(parseFloat(cellA)) && isFinite(cellA);
        
        if (isNum) {
            cellA = parseFloat(cellA);
            cellB = parseFloat(cellB);
            return currentSortDir === 'asc' ? cellA - cellB : cellB - cellA;
        } else {
            if (cellA < cellB) return currentSortDir === 'asc' ? -1 : 1;
            if (cellA > cellB) return currentSortDir === 'asc' ? 1 : -1;
            return 0;
        }
    });

    // Reinsertar las filas en el nuevo orden
    rows.forEach(row => tbody.appendChild(row));
    
    // Actualizar indicador visual (simple)
    const headers = table.querySelectorAll('th i');
    headers.forEach(h => h.className = 'fa-solid fa-sort'); // Reset
    const activeHeaderIcon = table.querySelectorAll('th')[n].querySelector('i');
    if(activeHeaderIcon) {
        activeHeaderIcon.className = currentSortDir === 'asc' ? 'fa-solid fa-sort-up' : 'fa-solid fa-sort-down';
    }
}

function limpiarTodo() {
    document.getElementById('ioc-input').value = '';
    document.querySelector('#results-table tbody').innerHTML = '';
    document.getElementById('progress-container').style.display = 'none';
    document.getElementById('stats-summary').style.display = 'none';
}

