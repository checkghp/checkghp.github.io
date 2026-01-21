/**
 * Main Application Logic
 * GitHub Education - Student Developer Pack Credentials Page
 */

import { Icons } from './icons.js';
import { escapeHtml, copyToClipboard } from './utils.js';
import { initLogsPanel } from './logs.js';
import { generateTOTP, getTimeRemaining, generateOTPAuthURL } from './totp.js';

// Store parsed credentials globally
let credentials = null;

/**
 * Parse credentials from URL hash
 * Expected format: base64(email:password:2fa:token)
 * 
 * @returns {Object|null} - Parsed credentials or null if invalid
 */
function parseCredentials() {
    const hash = window.location.hash.substring(1);
    
    if (!hash) {
        return null;
    }

    try {
        const decoded = atob(hash);
        const parts = decoded.split(':');
        
        if (parts.length < 2) {
            return null;
        }

        return {
            email: parts[0] || '',
            password: parts[1] || '',
            twofa: parts[2] || '',
            token: parts[3] || ''
        };
    } catch (error) {
        console.error('Failed to parse credentials:', error);
        return null;
    }
}

/**
 * Get icon for credential type
 * @param {string} type - Credential type
 * @returns {string} - SVG icon
 */
function getCredentialIcon(type) {
    const iconMap = {
        email: Icons.email,
        password: Icons.key,
        twofa: Icons.shield,
        token: Icons.token
    };
    return iconMap[type] || Icons.key;
}

/**
 * Render credentials display
 * Shows login, password, 2FA code, and token with copy functionality
 */
function renderCredentials() {
    const container = document.getElementById('credentialsContainer');

    if (!credentials) {
        renderNoCredentials(container);
        return;
    }

    const credentialItems = [
        { key: 'email', label: 'Почта', icon: 'email', value: credentials.email },
        { key: 'password', label: 'Пароль', icon: 'password', value: credentials.password },
        { key: 'twofa', label: '2FA Secret', icon: 'twofa', value: credentials.twofa },
        { key: 'token', label: 'Personal Access Token', icon: 'token', value: credentials.token }
    ].filter(item => item.value);

    const itemsHtml = credentialItems.map(item => `
        <div class="credential-item" onclick="window.app.handleItemClick(event, '${escapeHtml(item.value)}')">
            <div class="credential-icon ${item.icon}">
                ${getCredentialIcon(item.icon)}
            </div>
            <div class="credential-info">
                <div class="credential-label">${item.label}</div>
                <div class="credential-value">${escapeHtml(item.value)}</div>
            </div>
            <button class="copy-btn" onclick="event.stopPropagation(); window.app.copyToClipboard('${escapeHtml(item.value)}', this)">
                ${Icons.copy}
            </button>
        </div>
    `).join('');

    // Check if we have 2FA secret for TOTP
    const hasTwoFA = credentials.twofa && credentials.twofa.length > 0;
    const totpHtml = hasTwoFA ? `
        <div class="totp-section">
            <p class="totp-hint">Нажмите, чтобы скопировать</p>
            <div class="totp-display" id="totpDisplay">
                <div class="totp-code" id="totpCode">--- ---</div>
                <button class="totp-copy-icon" id="copyTotpBtn">
                    ${Icons.copy}
                </button>
            </div>
            <div class="totp-progress-bar">
                <div class="totp-progress" id="totpProgress"></div>
            </div>
        </div>
        
        <div class="qr-section">
            <div class="qr-header">
                <h3>QR-код для приложения</h3>
                <p>Сканируйте в Яндекс.Ключ или Google Authenticator</p>
            </div>
            <div class="qr-code" id="qrCode"></div>
        </div>
    ` : '';

    // App store links HTML
    const appLinksHtml = hasTwoFA ? `
        <div class="auth-apps-section">
            <h3>Скачать приложение для 2FA</h3>
            <div class="app-cards">
                <div class="app-card">
                    <div class="app-card-header">
                        <img src="icon/yandex.key.webp" alt="Яндекс.Ключ" class="app-logo">
                        <div class="app-title">
                            <span class="app-name">Яндекс.Ключ</span>
                            <span class="app-desc">Менеджер паролей и 2FA</span>
                        </div>
                    </div>
                    <div class="app-links">
                        <a href="https://play.google.com/store/apps/details?id=ru.yandex.key" target="_blank" class="store-link android">
                            <span>Google Play</span>
                        </a>
                        <a href="https://apps.apple.com/ru/app/%D1%8F%D0%BD%D0%B4%D0%B5%D0%BA%D1%81-id-%D0%BA%D0%BB%D1%8E%D1%87%D0%B8-%D0%B8-%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D0%B8/id957324816" target="_blank" class="store-link ios">
                            <span>App Store</span>
                        </a>
                    </div>
                </div>
                <div class="app-card">
                    <div class="app-card-header">
                        <img src="icon/google.auth.webp" alt="Google Authenticator" class="app-logo">
                        <div class="app-title">
                            <span class="app-name">Google Authenticator</span>
                            <span class="app-desc">2FA от Google</span>
                        </div>
                    </div>
                    <div class="app-links">
                        <a href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2" target="_blank" class="store-link android">
                            <span>Google Play</span>
                        </a>
                        <a href="https://apps.apple.com/ru/app/google-authenticator/id388497605" target="_blank" class="store-link ios">
                            <span>App Store</span>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    ` : '';

    container.innerHTML = `
        <div class="credentials-card">
            <div class="credentials-body">
                ${itemsHtml}
            </div>
        </div>
        ${totpHtml}
        ${appLinksHtml}
    `;
    
    // Initialize TOTP if we have 2FA secret
    if (hasTwoFA) {
        initTOTP(credentials.twofa, credentials.email);
    }
}

/**
 * Render error state when no credentials provided
 * @param {HTMLElement} container - Container to render into
 */
function renderNoCredentials(container) {
    container.innerHTML = `
        <div class="error-container">
            <div class="error-icon">${Icons.error}</div>
            <h2>Данные не найдены</h2>
            <p>Добавьте данные в формате base64 после знака # в URL</p>
        </div>
    `;
}

/**
 * Handle click on credential item
 * @param {Event} event - Click event
 * @param {string} value - Value to copy
 */
function handleItemClick(event, value) {
    const button = event.currentTarget.querySelector('.copy-btn');
    copyToClipboard(value, button);
}

// Store current TOTP code
let currentTOTPCode = '';
let totpInterval = null;
let animationFrameId = null;

/**
 * Initialize TOTP display and QR code
 * @param {string} secret - Base32 secret
 * @param {string} account - Account name
 */
async function initTOTP(secret, account) {
    // Generate QR code
    const qrContainer = document.getElementById('qrCode');
    const otpURL = generateOTPAuthURL(secret, account, 'GitHub');
    
    // Use QR Server API for QR code generation (white QR on dark background)
    const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpURL)}&bgcolor=21262d&color=ffffff&format=svg&margin=10`;
    qrContainer.innerHTML = `<img src="${qrImageUrl}" alt="QR Code" width="200" height="200">`;
    
    // Setup copy button
    const copyBtn = document.getElementById('copyTotpBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (currentTOTPCode) {
                copyToClipboard(currentTOTPCode, copyBtn);
            }
        });
    }
    
    // Make entire display clickable for copy
    const displayEl = document.getElementById('totpDisplay');
    if (displayEl) {
        displayEl.addEventListener('click', () => {
            if (currentTOTPCode) {
                copyToClipboard(currentTOTPCode, copyBtn);
            }
        });
    }
    
    // Initial TOTP generation
    await refreshTOTPCode(secret);
    
    // Start smooth animation loop
    startProgressAnimation(secret);
}

/**
 * Refresh TOTP code
 * @param {string} secret - Base32 secret
 */
async function refreshTOTPCode(secret) {
    try {
        currentTOTPCode = await generateTOTP(secret);
        const codeEl = document.getElementById('totpCode');
        if (codeEl) {
            codeEl.textContent = currentTOTPCode.slice(0, 3) + ' ' + currentTOTPCode.slice(3);
        }
    } catch (e) {
        console.error('Failed to generate TOTP:', e);
    }
}

/**
 * Interpolate between two colors
 * @param {Array} color1 - RGB array [r, g, b]
 * @param {Array} color2 - RGB array [r, g, b]
 * @param {number} factor - 0 to 1
 * @returns {string} - RGB string
 */
function interpolateColor(color1, color2, factor) {
    const r = Math.round(color1[0] + (color2[0] - color1[0]) * factor);
    const g = Math.round(color1[1] + (color2[1] - color1[1]) * factor);
    const b = Math.round(color1[2] + (color2[2] - color1[2]) * factor);
    return `rgb(${r}, ${g}, ${b})`;
}

/**
 * Get gradient colors based on remaining time
 * @param {number} scale - 0 to 1 (1 = full time, 0 = no time)
 * @returns {string} - CSS gradient
 */
function getProgressGradient(scale) {
    // Color stops: green -> yellow -> orange -> red
    const green = [35, 134, 54];      // #238636
    const greenLight = [46, 160, 67]; // #2ea043
    const yellow = [210, 153, 34];    // #d29922
    const orange = [247, 129, 102];   // #f78166
    const red = [248, 81, 73];        // #f85149
    const redDark = [218, 54, 51];    // #da3633
    
    let color1, color2, color1Light, color2Light;
    let factor;
    
    if (scale > 0.66) {
        // Green zone (100% - 66%)
        factor = (1 - scale) / 0.34;
        color1 = interpolateColor(green, yellow, factor);
        color2 = interpolateColor(greenLight, yellow, factor);
        return `linear-gradient(90deg, ${color1}, ${color2})`;
    } else if (scale > 0.33) {
        // Yellow-Orange zone (66% - 33%)
        factor = (0.66 - scale) / 0.33;
        color1 = interpolateColor(yellow, orange, factor);
        color2 = interpolateColor(yellow, orange, factor * 0.8);
        return `linear-gradient(90deg, ${color1}, ${color2})`;
    } else {
        // Red zone (33% - 0%)
        factor = (0.33 - scale) / 0.33;
        color1 = interpolateColor(orange, red, factor);
        color2 = interpolateColor(orange, redDark, factor);
        return `linear-gradient(90deg, ${color1}, ${color2})`;
    }
}

/**
 * Start smooth progress animation using requestAnimationFrame
 * @param {string} secret - Base32 secret
 */
function startProgressAnimation(secret) {
    const progressEl = document.getElementById('totpProgress');
    let lastCodeTime = Math.floor(Date.now() / 30000) * 30000;
    
    function animate() {
        const now = Date.now();
        const currentCodeTime = Math.floor(now / 30000) * 30000;
        
        // Check if we need to refresh the code
        if (currentCodeTime !== lastCodeTime) {
            lastCodeTime = currentCodeTime;
            refreshTOTPCode(secret);
        }
        
        // Calculate smooth scale from 1 to 0
        const elapsed = now - currentCodeTime;
        const scale = 1 - (elapsed / 30000); // 1 to 0 over 30 seconds
        
        // Update progress bar with smooth transform and color
        if (progressEl) {
            progressEl.style.transform = `scaleX(${scale})`;
            progressEl.style.background = getProgressGradient(scale);
        }
        
        animationFrameId = requestAnimationFrame(animate);
    }
    
    if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
    }
    
    animate();
}

/**
 * Initialize the application
 */
function init() {
    credentials = parseCredentials();
    renderCredentials();
    initLogsPanel();
}

// Expose functions to global scope
window.app = {
    copyToClipboard,
    handleItemClick
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);
