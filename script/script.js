// script/script.js

/**
 * CyberSecurity Dashboard
 * Sistema completo de análise de segurança e privacidade
 */

// Variáveis globais
let securityScore = 50; // Score base melhorado
let detectedExtensions = [];

// Inicializa o dashboard quando o DOM carregar
document.addEventListener('DOMContentLoaded', function() {
    console.log('%c🔒 CyberSecurity Dashboard Iniciado', 'color: #667fff; font-size: 20px; font-weight: bold;');
    
    // Inicia todas as análises
    initializeAnalysis();
});

/**
 * Inicializa todas as análises
 */
async function initializeAnalysis() {
    // Informações básicas do navegador
    getBrowserInfo();
    getScreenInfo();
    getAdditionalInfo();
    
    // Informações de rede - tenta múltiplas APIs
    await getIPInfo();
    getWebRTCInfo();
    
    // Recursos de segurança
    checkSecurityFeatures();
    
    // Detecta extensões
    detectExtensions();
    
    // Gera fingerprint
    generateFingerprint();
    
    // Atualiza relógio
    updateClock();
    setInterval(updateClock, 1000);
    
    // Calcula score de segurança
    calculateSecurityScore();
}

/**
 * Obtém informações do navegador
 */
function getBrowserInfo() {
    const ua = navigator.userAgent;
    let browserName = 'Desconhecido';
    let browserVersion = '';
    let os = 'Desconhecido';
    
    // Detecta navegador
    if (ua.indexOf('Firefox') > -1) {
        browserName = 'Firefox';
        browserVersion = ua.match(/Firefox\/([0-9.]+)/)?.[1] || '';
        securityScore += 5; // Firefox é focado em privacidade
    } else if (ua.indexOf('Edg') > -1) {
        browserName = 'Microsoft Edge';
        browserVersion = ua.match(/Edg\/([0-9.]+)/)?.[1] || '';
        securityScore += 3;
    } else if (ua.indexOf('Chrome') > -1) {
        browserName = 'Google Chrome';
        browserVersion = ua.match(/Chrome\/([0-9.]+)/)?.[1] || '';
        securityScore += 2;
    } else if (ua.indexOf('Safari') > -1) {
        browserName = 'Safari';
        browserVersion = ua.match(/Version\/([0-9.]+)/)?.[1] || '';
        securityScore += 4; // Safari tem boas proteções
    } else if (ua.indexOf('Opera') > -1 || ua.indexOf('OPR') > -1) {
        browserName = 'Opera';
        browserVersion = ua.match(/(?:Opera|OPR)\/([0-9.]+)/)?.[1] || '';
        securityScore += 3;
    }
    
    // Detecta SO
    if (ua.indexOf('Windows NT 10.0') > -1) os = 'Windows 10/11';
    else if (ua.indexOf('Windows NT 6.3') > -1) os = 'Windows 8.1';
    else if (ua.indexOf('Windows NT 6.2') > -1) os = 'Windows 8';
    else if (ua.indexOf('Windows NT 6.1') > -1) os = 'Windows 7';
    else if (ua.indexOf('Mac OS X') > -1) {
        os = 'macOS';
        securityScore += 5; // macOS tem boa segurança nativa
    } else if (ua.indexOf('Linux') > -1) {
        os = 'Linux';
        securityScore += 8; // Linux usuários geralmente são mais conscientes de segurança
    } else if (ua.indexOf('Android') > -1) os = 'Android';
    else if (ua.indexOf('iOS') > -1) {
        os = 'iOS';
        securityScore += 5;
    }
    
    // Atualiza DOM
    document.getElementById('browserName').textContent = browserName;
    document.getElementById('browserVersion').textContent = browserVersion || 'N/A';
    document.getElementById('os').textContent = os;
    document.getElementById('platform').textContent = navigator.platform || 'N/A';
    document.getElementById('language').textContent = navigator.language || 'N/A';
    document.getElementById('cookies').textContent = navigator.cookieEnabled ? 'Sim ✓' : 'Não ✗';
    document.getElementById('userAgent').textContent = ua;
}

/**
 * Obtém informações da tela
 */
function getScreenInfo() {
    const screen = window.screen;
    const deviceMemory = navigator.deviceMemory || 'N/A';
    const cpuCores = navigator.hardwareConcurrency || 'N/A';
    
    document.getElementById('screenResolution').textContent = 
        `${screen.width} x ${screen.height}`;
    document.getElementById('windowSize').textContent = 
        `${window.innerWidth} x ${window.innerHeight}`;
    document.getElementById('colorDepth').textContent = 
        `${screen.colorDepth}-bit`;
    document.getElementById('cpuCores').textContent = cpuCores !== 'N/A' ? `${cpuCores} cores` : cpuCores;
    document.getElementById('deviceMemory').textContent = 
        deviceMemory !== 'N/A' ? `${deviceMemory} GB` : deviceMemory;
    document.getElementById('timezone').textContent = 
        Intl.DateTimeFormat().resolvedOptions().timeZone;
}

/**
 * Obtém informações de IP público - Tenta múltiplas APIs
 */
async function getIPInfo() {
    const apis = [
        {
            url: 'https://api.ipify.org?format=json',
            parse: async (response) => {
                const data = await response.json();
                return {
                    ip: data.ip,
                    location: 'Localização não disponível (API limitada)',
                    isp: 'Provedor não disponível (API limitada)',
                    vpn: false
                };
            }
        },
        {
            url: 'https://ipapi.co/json/',
            parse: async (response) => {
                const data = await response.json();
                return {
                    ip: data.ip,
                    location: `${data.city || 'N/A'}, ${data.region || 'N/A'}, ${data.country_name || 'N/A'}`,
                    isp: data.org || 'Não detectado',
                    vpn: data.threat?.is_vpn || data.threat?.is_proxy || false
                };
            }
        },
        {
            url: 'https://api.db-ip.com/v2/free/self',
            parse: async (response) => {
                const data = await response.json();
                return {
                    ip: data.ipAddress,
                    location: `${data.city || 'N/A'}, ${data.stateProv || 'N/A'}, ${data.countryName || 'N/A'}`,
                    isp: 'Provedor não disponível (API limitada)',
                    vpn: false
                };
            }
        },
        {
            url: 'https://api.ipgeolocation.io/ipgeo?apiKey=free',
            parse: async (response) => {
                const data = await response.json();
                return {
                    ip: data.ip,
                    location: `${data.city || 'N/A'}, ${data.state_prov || 'N/A'}, ${data.country_name || 'N/A'}`,
                    isp: data.isp || 'Não detectado',
                    vpn: false
                };
            }
        }
    ];

    for (const api of apis) {
        try {
            console.log(`Tentando obter IP de: ${api.url}`);
            const response = await fetch(api.url, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await api.parse(response);
                
                document.getElementById('publicIP').textContent = data.ip || 'Não detectado';
                document.getElementById('location').textContent = data.location;
                document.getElementById('isp').textContent = data.isp;
                
                // Verifica VPN/Proxy
                const isVPN = data.vpn;
                document.getElementById('vpnStatus').textContent = isVPN ? 'Sim (Detectado) ⚠️' : 'Não detectado';
                
                if (isVPN) {
                    securityScore += 15; // VPN aumenta segurança
                }
                
                console.log('✅ IP obtido com sucesso!');
                return; // Sucesso, sai da função
            }
        } catch (error) {
            console.warn(`Erro ao obter IP de ${api.url}:`, error.message);
            continue; // Tenta próxima API
        }
    }
    
    // Se todas falharem
    console.error('❌ Todas as APIs de IP falharam');
    document.getElementById('publicIP').textContent = 'Não foi possível detectar';
    document.getElementById('location').textContent = 'Não foi possível detectar';
    document.getElementById('isp').textContent = 'Não foi possível detectar';
    document.getElementById('vpnStatus').textContent = 'Não foi possível verificar';
}

/**
 * Obtém IP local via WebRTC
 */
function getWebRTCInfo() {
    const RTCPeerConnection = window.RTCPeerConnection || 
                             window.mozRTCPeerConnection || 
                             window.webkitRTCPeerConnection;
    
    if (!RTCPeerConnection) {
        document.getElementById('localIP').textContent = 'WebRTC não suportado';
        securityScore += 10; // WebRTC desabilitado é mais seguro
        return;
    }
    
    const pc = new RTCPeerConnection({iceServers: []});
    const noop = () => {};
    
    pc.createDataChannel('');
    pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(noop);
    
    pc.onicecandidate = (ice) => {
        if (!ice || !ice.candidate || !ice.candidate.candidate) return;
        
        const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/;
        const match = ipRegex.exec(ice.candidate.candidate);
        
        if (match) {
            document.getElementById('localIP').textContent = match[1];
            pc.onicecandidate = noop;
        }
    };
    
    // Timeout se não detectar em 3 segundos
    setTimeout(() => {
        if (document.getElementById('localIP').textContent === 'Detectando...') {
            document.getElementById('localIP').textContent = 'Bloqueado (Seguro) 🛡️';
            securityScore += 10; // IP local bloqueado é bom para privacidade
        }
    }, 3000);
    
    // Info de conexão
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (connection) {
        document.getElementById('connectionType').textContent = connection.effectiveType || 'N/A';
        document.getElementById('downlink').textContent = connection.downlink ? `${connection.downlink} Mbps` : 'N/A';
        document.getElementById('rtt').textContent = connection.rtt ? `${connection.rtt} ms` : 'N/A';
    } else {
        document.getElementById('connectionType').textContent = 'N/A';
        document.getElementById('downlink').textContent = 'N/A';
        document.getElementById('rtt').textContent = 'N/A';
    }
    
    // Info de bateria
    if ('getBattery' in navigator) {
        navigator.getBattery().then(battery => {
            document.getElementById('battery').textContent = `${Math.round(battery.level * 100)}%`;
            document.getElementById('charging').textContent = battery.charging ? 'Sim 🔌' : 'Não';
        });
    } else {
        document.getElementById('battery').textContent = 'N/A';
        document.getElementById('charging').textContent = 'N/A';
    }
}

/**
 * Verifica recursos de segurança
 */
function checkSecurityFeatures() {
    // Do Not Track
    const dnt = navigator.doNotTrack || window.doNotTrack || navigator.msDoNotTrack;
    const dntEnabled = dnt === '1' || dnt === 'yes';
    updateSecurityItem('dntItem', 'dntStatus', dntEnabled, 'Ativado ✓', 'Desativado ✗');
    if (dntEnabled) securityScore += 10;
    
    // Java
    const javaEnabled = navigator.javaEnabled ? navigator.javaEnabled() : false;
    updateSecurityItem('javaItem', 'javaStatus', !javaEnabled, 'Desabilitado (Seguro) ✓', 'Habilitado (Risco) ⚠️');
    if (!javaEnabled) securityScore += 15;
    
    // WebGL
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    const webglEnabled = !!gl;
    updateSecurityItem('webglItem', 'webglStatus', webglEnabled, 'Suportado ✓', 'Não suportado');
    
    // Canvas Fingerprinting
    const canvasSupported = !!canvas.getContext('2d');
    updateSecurityItem('canvasItem', 'canvasStatus', canvasSupported, 'Detectável ⚠️', 'Bloqueado ✓');
    if (!canvasSupported) securityScore += 5;
    
    // AdBlock
    checkAdBlock();
    
    // Touch
    const touchEnabled = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    updateSecurityItem('touchItem', 'touchStatus', touchEnabled, 'Habilitado', 'Não disponível');
    
    // HTTPS
    if (window.location.protocol === 'https:') {
        securityScore += 10;
    }
}

/**
 * Verifica AdBlock
 */
function checkAdBlock() {
    const adDiv = document.createElement('div');
    adDiv.className = 'ad ads adsbygoogle ad-placement ad-placeholder';
    adDiv.style.height = '1px';
    document.body.appendChild(adDiv);
    
    setTimeout(() => {
        const adBlocked = adDiv.offsetHeight === 0;
        updateSecurityItem('adBlockItem', 'adBlockStatus', adBlocked, 'Sim (Protegido) 🛡️', 'Não ✗');
        document.body.removeChild(adDiv);
        if (adBlocked) securityScore += 20; // AdBlock é muito importante
    }, 100);
}

/**
 * Atualiza item de segurança
 */
function updateSecurityItem(itemId, statusId, condition, trueText, falseText) {
    const statusEl = document.getElementById(statusId);
    statusEl.textContent = condition ? trueText : falseText;
    statusEl.className = 'security-status ' + (condition ? 'status-enabled' : 'status-disabled');
}

/**
 * Detecta extensões do navegador
 */
function detectExtensions() {
    const extensions = [];
    const extensionsToCheck = [
        { name: 'AdBlock Plus', check: () => typeof window.adblockplus !== 'undefined' },
        { name: 'uBlock Origin', check: () => typeof window.uBlock !== 'undefined' },
        { name: 'Grammarly', check: () => typeof window.grammarly !== 'undefined' },
        { name: 'LastPass', check: () => typeof window.LPlatform !== 'undefined' },
        { name: 'Ghostery', check: () => typeof window.GhosteryGlobal !== 'undefined' },
        { name: 'Honey', check: () => typeof window.honey !== 'undefined' },
        { name: 'Privacy Badger', check: () => typeof window.privacyBadger !== 'undefined' },
        { name: 'HTTPS Everywhere', check: () => typeof window.httpsEverywhere !== 'undefined' },
        { name: 'Tampermonkey', check: () => typeof window.GM_info !== 'undefined' },
        { name: 'MetaMask', check: () => typeof window.ethereum !== 'undefined' && window.ethereum.isMetaMask }
    ];
    
    extensionsToCheck.forEach(ext => {
        if (ext.check()) {
            extensions.push(ext.name);
        }
    });
    
    // Adiciona pontos por extensões de segurança
    securityScore += extensions.length * 5;
    
    const container = document.getElementById('extensionsContainer');
    
    if (extensions.length === 0) {
        container.innerHTML = `
            <div class="loading-state">
                <i class="fas fa-puzzle-piece"></i>
                <span>Nenhuma extensão detectada (detecção limitada)</span>
                <p style="font-size: 12px; margin-top: 8px; color: var(--text-muted);">
                    Instale extensões de privacidade para aumentar sua segurança!
                </p>
            </div>
        `;
    } else {
        let html = '<div class="extension-list">';
        extensions.forEach(ext => {
            html += `
                <div class="extension-item">
                    <div class="extension-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <span class="extension-name">${ext}</span>
                </div>
            `;
        });
        html += '</div>';
        container.innerHTML = html;
    }
}

/**
 * Verifica permissões
 */
async function checkPermission(type) {
    const statusEl = document.getElementById(`perm-${type}`);
    
    try {
        if (type === 'geolocation') {
            navigator.geolocation.getCurrentPosition(
                () => {
                    statusEl.textContent = 'Permitido ✓';
                    statusEl.style.background = 'rgba(16, 185, 129, 0.15)';
                    statusEl.style.color = '#10b981';
                },
                () => {
                    statusEl.textContent = 'Negado (Seguro) 🛡️';
                    statusEl.style.background = 'rgba(16, 185, 129, 0.15)';
                    statusEl.style.color = '#10b981';
                    securityScore += 8;
                    calculateSecurityScore();
                }
            );
        } else if (type === 'notifications') {
            const result = await Notification.requestPermission();
            if (result === 'granted') {
                statusEl.textContent = 'Permitido ✓';
                statusEl.style.background = 'rgba(245, 158, 11, 0.15)';
                statusEl.style.color = '#f59e0b';
            } else {
                statusEl.textContent = 'Negado (Seguro) 🛡️';
                statusEl.style.background = 'rgba(16, 185, 129, 0.15)';
                statusEl.style.color = '#10b981';
                securityScore += 8;
                calculateSecurityScore();
            }
        } else if (type === 'camera' || type === 'microphone') {
            const constraints = type === 'camera' ? { video: true } : { audio: true };
            navigator.mediaDevices.getUserMedia(constraints)
                .then(() => {
                    statusEl.textContent = 'Permitido ⚠️';
                    statusEl.style.background = 'rgba(245, 158, 11, 0.15)';
                    statusEl.style.color = '#f59e0b';
                })
                .catch(() => {
                    statusEl.textContent = 'Negado (Seguro) 🛡️';
                    statusEl.style.background = 'rgba(16, 185, 129, 0.15)';
                    statusEl.style.color = '#10b981';
                    securityScore += 8;
                    calculateSecurityScore();
                });
        }
    } catch (error) {
        statusEl.textContent = 'Bloqueado 🛡️';
        statusEl.style.background = 'rgba(16, 185, 129, 0.15)';
        statusEl.style.color = '#10b981';
        securityScore += 8;
        calculateSecurityScore();
    }
}

/**
 * Gera fingerprint único
 */
function generateFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('CyberSec', 2, 2);
    
    const canvasData = canvas.toDataURL();
    const screen = `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`;
    const plugins = Array.from(navigator.plugins || []).map(p => p.name).join(',');
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    
    const data = `${navigator.userAgent}${screen}${plugins}${timezone}${canvasData}${navigator.language}`;
    
    // Simple hash
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
        const char = data.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    
    const fingerprint = Math.abs(hash).toString(16).toUpperCase().padStart(16, '0');
    document.getElementById('fingerprint').textContent = fingerprint;
}

/**
 * Obtém informações adicionais
 */
function getAdditionalInfo() {
    document.getElementById('referrer').textContent = document.referrer || 'Direto (Seguro) ✓';
    document.getElementById('currentURL').textContent = window.location.href;
    
    // Storage
    try {
        sessionStorage.setItem('test', 'test');
        sessionStorage.removeItem('test');
        document.getElementById('sessionStorage').textContent = 'Habilitado ✓';
    } catch (e) {
        document.getElementById('sessionStorage').textContent = 'Desabilitado (Seguro) 🛡️';
        securityScore += 8;
    }
    
    try {
        localStorage.setItem('test', 'test');
        localStorage.removeItem('test');
        document.getElementById('localStorage').textContent = 'Habilitado ✓';
    } catch (e) {
        document.getElementById('localStorage').textContent = 'Desabilitado (Seguro) 🛡️';
        securityScore += 8;
    }
    
    document.getElementById('indexedDB').textContent = 
        window.indexedDB ? 'Suportado ✓' : 'Não suportado';
}

/**
 * Atualiza relógio
 */
function updateClock() {
    const now = new Date();
    const formatted = now.toLocaleString('pt-BR', {
        dateStyle: 'full',
        timeStyle: 'long'
    });
    document.getElementById('localTime').textContent = formatted;
}

/**
 * Calcula score de segurança
 */
function calculateSecurityScore() {
    setTimeout(() => {
        const scoreEl = document.getElementById('scoreValue');
        const maxScore = 200; // Score máximo aumentado
        const percentage = Math.min(Math.round((securityScore / maxScore) * 100), 100);
        
        let level = '';
        let color = '';
        let icon = '';
        
        if (percentage >= 80) {
            level = 'Excelente';
            icon = '🛡️';
            color = '#10b981';
        } else if (percentage >= 60) {
            level = 'Bom';
            icon = '✓';
            color = '#10b981';
        } else if (percentage >= 40) {
            level = 'Médio';
            icon = '⚠️';
            color = '#f59e0b';
        } else {
            level = 'Baixo';
            icon = '⚠️';
            color = '#ef4444';
        }
        
        scoreEl.textContent = `${percentage}/100 - ${level} ${icon}`;
        scoreEl.style.color = color;
        
        // Atualiza ícone do badge
        const badgeIcon = document.querySelector('.badge-icon');
        if (percentage >= 60) {
            badgeIcon.style.background = 'rgba(16, 185, 129, 0.15)';
            badgeIcon.style.color = '#10b981';
        } else if (percentage >= 40) {
            badgeIcon.style.background = 'rgba(245, 158, 11, 0.15)';
            badgeIcon.style.color = '#f59e0b';
        } else {
            badgeIcon.style.background = 'rgba(239, 68, 68, 0.15)';
            badgeIcon.style.color = '#ef4444';
        }
        
        console.log('%c🔒 Score de Segurança:', 'color: #667fff; font-weight: bold;', `${percentage}/100 (${securityScore} pontos)`);
    }, 2500);
}

// Exporta funções globais
window.checkPermission = checkPermission;

console.log('%c✅ Dashboard Carregado com Sucesso!', 'color: #10b981; font-size: 14px; font-weight: bold;');