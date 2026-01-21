/**
 * TOTP (Time-based One-Time Password) Generator
 * Implements RFC 6238 for generating 2FA codes
 */

/**
 * Base32 alphabet
 */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decode base32 string to Uint8Array
 * @param {string} str - Base32 encoded string
 * @returns {Uint8Array}
 */
function base32Decode(str) {
    str = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
    
    const output = [];
    let bits = 0;
    let value = 0;
    
    for (let i = 0; i < str.length; i++) {
        const idx = BASE32_ALPHABET.indexOf(str[i]);
        if (idx === -1) continue;
        
        value = (value << 5) | idx;
        bits += 5;
        
        if (bits >= 8) {
            output.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    
    return new Uint8Array(output);
}

/**
 * Convert number to 8-byte big-endian buffer
 * @param {number} num - Number to convert
 * @returns {Uint8Array}
 */
function intToBytes(num) {
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    // Split into high and low 32-bit parts
    view.setUint32(0, Math.floor(num / 0x100000000));
    view.setUint32(4, num >>> 0);
    return new Uint8Array(buffer);
}

/**
 * Generate HMAC-SHA1 hash using Web Crypto API
 * @param {Uint8Array} key - Secret key
 * @param {Uint8Array} message - Message to hash
 * @returns {Promise<Uint8Array>}
 */
async function hmacSha1(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
    return new Uint8Array(signature);
}

/**
 * Generate TOTP code
 * @param {string} secret - Base32 encoded secret
 * @param {number} [timeStep=30] - Time step in seconds
 * @param {number} [digits=6] - Number of digits in code
 * @returns {Promise<string>}
 */
export async function generateTOTP(secret, timeStep = 30, digits = 6) {
    const key = base32Decode(secret);
    const time = Math.floor(Date.now() / 1000);
    const counter = Math.floor(time / timeStep);
    
    const counterBytes = intToBytes(counter);
    const hmac = await hmacSha1(key, counterBytes);
    
    // Dynamic truncation
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary = 
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    
    const otp = binary % Math.pow(10, digits);
    return otp.toString().padStart(digits, '0');
}

/**
 * Get time remaining until next code
 * @param {number} [timeStep=30] - Time step in seconds
 * @returns {number} - Seconds remaining
 */
export function getTimeRemaining(timeStep = 30) {
    const time = Math.floor(Date.now() / 1000);
    return timeStep - (time % timeStep);
}

/**
 * Generate OTP Auth URL for QR code
 * @param {string} secret - Base32 secret
 * @param {string} account - Account name
 * @param {string} issuer - Issuer name
 * @returns {string}
 */
export function generateOTPAuthURL(secret, account, issuer = 'GitHub') {
    return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
}

/**
 * Parse OTP Auth URL
 * @param {string} url - OTP Auth URL
 * @returns {Object|null}
 */
export function parseOTPAuthURL(url) {
    try {
        const match = url.match(/otpauth:\/\/totp\/([^?]+)\?(.+)/);
        if (!match) return null;
        
        const label = decodeURIComponent(match[1]);
        const params = new URLSearchParams(match[2]);
        
        return {
            label,
            secret: params.get('secret'),
            issuer: params.get('issuer') || '',
            algorithm: params.get('algorithm') || 'SHA1',
            digits: parseInt(params.get('digits') || '6'),
            period: parseInt(params.get('period') || '30')
        };
    } catch (e) {
        return null;
    }
}
