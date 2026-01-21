/**
 * Security Logs Analyzer
 * Handles .gz file upload, decompression, parsing and analysis
 */

import { Icons } from './icons.js';
import { escapeHtml, formatDate } from './utils.js';

/**
 * Decompress gzip data using DecompressionStream API
 * @param {ArrayBuffer} compressedData - Gzipped data
 * @returns {Promise<string>} - Decompressed text
 */
async function decompressGzip(compressedData) {
    if (typeof DecompressionStream === 'undefined') {
        throw new Error('Браузер не поддерживает DecompressionStream. Используйте Chrome, Edge или Firefox.');
    }
    
    const stream = new Response(compressedData).body
        .pipeThrough(new DecompressionStream('gzip'));
    
    const decompressed = await new Response(stream).text();
    return decompressed;
}

/**
 * Parse NDJSON (newline-delimited JSON)
 * @param {string} text - NDJSON text
 * @returns {Array} - Array of parsed objects
 */
function parseNDJSON(text) {
    const lines = text.trim().split('\n');
    const events = [];
    
    for (const line of lines) {
        if (line.trim()) {
            try {
                events.push(JSON.parse(line));
            } catch (e) {
                console.warn('Failed to parse line:', line);
            }
        }
    }
    
    return events;
}

/**
 * Analyze logs and check account integrity
 * @param {Array} events - Parsed events
 * @returns {Object} - Analysis results with checks
 */
function analyzeLogs(events) {
    const sorted = [...events].sort((a, b) => a['@timestamp'] - b['@timestamp']);
    
    // Дата создания аккаунта
    const createEvent = sorted.find(e => e.action === 'user.create');
    
    // Почта из события создания аккаунта
    const originalEmail = createEvent?.email || null;
    
    // Проверка почты
    const emailEvents = sorted.filter(e => 
        e.action === 'user.email_create' || 
        e.action === 'user.email_delete' || 
        e.action === 'user.primary_email_changed'
    );
    
    // Проверка пароля
    const passwordEvents = sorted.filter(e => 
        e.action === 'user.password_reset' || 
        e.action === 'user.password_changed'
    );
    
    // Проверка 2FA
    const twoFaChanges = sorted.filter(e => 
        e.action === 'two_factor_authentication.enabled' || 
        e.action === 'two_factor_authentication.disabled'
    );
    
    // Результаты проверок
    const checks = {
        // Почта не менялась: только одно событие добавления почты и ноль изменений
        emailUnchanged: emailEvents.length <= 1,
        emailChangesCount: emailEvents.length - 1, // Минус первоначальное добавление
        
        // Пароль никогда не менялся
        passwordUnchanged: passwordEvents.length === 0,
        passwordChangesCount: passwordEvents.length,
        
        // 2FA не менялась (только одно включение, без отключений и повторных включений)
        twoFaUnchanged: twoFaChanges.length <= 1 && !twoFaChanges.some(e => e.action === 'two_factor_authentication.disabled'),
        twoFaChangesCount: twoFaChanges.length > 1 ? twoFaChanges.length - 1 : 0
    };
    
    // Все проверки пройдены
    checks.allPassed = checks.emailUnchanged && checks.passwordUnchanged && checks.twoFaUnchanged;
    
    return {
        accountCreated: createEvent ? new Date(createEvent['@timestamp']) : null,
        username: createEvent?.actor || events[0]?.actor || 'Unknown',
        originalEmail,
        checks,
        totalEvents: events.length
    };
}

/**
 * Render check item
 * @param {boolean} passed - Check passed
 * @param {string} label - Check label
 * @param {string} detail - Additional detail
 * @returns {string} - HTML string
 */
function renderCheckItem(passed, label) {
    const icon = passed ? Icons.check : Icons.close;
    const statusClass = passed ? 'check-passed' : 'check-failed';
    
    return `
        <div class="check-item ${statusClass}">
            <div class="check-icon">${icon}</div>
            <div class="check-label">${label}</div>
        </div>
    `;
}

/**
 * Render logs analysis UI
 * @param {Object} analysis - Analysis results
 * @param {HTMLElement} container - Container element
 */
function renderLogsAnalysis(analysis, container) {
    const { checks } = analysis;
    
    // Статус проверки
    const statusClass = checks.allPassed ? 'status-success' : 'status-warning';
    const statusIcon = checks.allPassed ? Icons.check : Icons.close;
    const statusText = checks.allPassed ? 'Аккаунт не изменён' : 'Обнаружены изменения';
    
    const html = `
        <div class="logs-analysis">
            <!-- Информация об аккаунте -->
            <div class="account-origin">
                <div class="origin-row">
                    <span class="origin-label">Почта:</span>
                    <span class="origin-value">${analysis.originalEmail ? escapeHtml(analysis.originalEmail) : 'Нет данных'}</span>
                </div>
                <div class="origin-row">
                    <span class="origin-label">Создан:</span>
                    <span class="origin-value">${analysis.accountCreated ? formatDate(analysis.accountCreated) : 'Нет данных'}</span>
                </div>
            </div>
            
            <!-- Общий статус -->
            <div class="verification-status ${statusClass}">
                <div class="status-icon">${statusIcon}</div>
                <div class="status-text">${statusText}</div>
            </div>
            
            <!-- Результаты проверок -->
            <div class="checks-list">
                ${renderCheckItem(checks.emailUnchanged, 'Почта не менялась')}
                ${renderCheckItem(checks.passwordUnchanged, 'Пароль не менялся')}
                ${renderCheckItem(checks.twoFaUnchanged, '2FA не менялась')}
            </div>
            
            <div class="logs-footer">
                Проанализировано ${analysis.totalEvents} событий
            </div>
        </div>
    `;
    
    container.innerHTML = html;
}

/**
 * Handle file upload
 * @param {File} file - Uploaded file
 * @param {HTMLElement} container - Results container
 */
async function handleFileUpload(file, container) {
    const statusEl = document.getElementById('uploadStatus');
    
    try {
        statusEl.innerHTML = `${Icons.loader} Загрузка файла...`;
        statusEl.className = 'upload-status loading';
        
        const arrayBuffer = await file.arrayBuffer();
        
        let text;
        if (file.name.endsWith('.gz')) {
            statusEl.innerHTML = `${Icons.loader} Распаковка gzip...`;
            text = await decompressGzip(arrayBuffer);
        } else {
            text = new TextDecoder().decode(arrayBuffer);
        }
        
        statusEl.innerHTML = `${Icons.loader} Анализ логов...`;
        const events = parseNDJSON(text);
        
        if (events.length === 0) {
            throw new Error('Файл не содержит событий');
        }
        
        const analysis = analyzeLogs(events);
        
        statusEl.innerHTML = '';
        statusEl.className = 'upload-status';
        
        renderLogsAnalysis(analysis, container);
        
    } catch (error) {
        console.error('Error processing file:', error);
        statusEl.innerHTML = `${Icons.error} Ошибка: ${escapeHtml(error.message)}`;
        statusEl.className = 'upload-status error';
    }
}

/**
 * Initialize logs panel
 */
export function initLogsPanel() {
    const uploadArea = document.getElementById('logsUploadArea');
    const fileInput = document.getElementById('logsFileInput');
    const resultsContainer = document.getElementById('logsResults');
    
    if (!uploadArea || !fileInput) return;
    
    uploadArea.addEventListener('click', () => fileInput.click());
    
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            handleFileUpload(file, resultsContainer);
        }
    });
    
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        
        const file = e.dataTransfer.files[0];
        if (file) {
            handleFileUpload(file, resultsContainer);
        }
    });
}
