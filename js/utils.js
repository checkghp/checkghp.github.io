/**
 * Utility functions for the application
 */

import { Icons } from './icons.js';

/**
 * Escape HTML special characters to prevent XSS attacks
 * @param {string} text - The text to escape
 * @returns {string} - Escaped text safe for HTML insertion
 */
export function escapeHtml(text) {
    if (!text) return '';
    
    const htmlEntities = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    
    return String(text).replace(/[&<>"']/g, char => htmlEntities[char]);
}

/**
 * Format a date string to a localized format
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date string
 */
export function formatDate(dateString) {
    if (!dateString) return 'Unknown';
    
    const date = new Date(dateString);
    const options = { 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric' 
    };
    
    return date.toLocaleDateString('ru-RU', options);
}

/**
 * Copy text to clipboard with visual feedback
 * @param {string} text - Text to copy
 * @param {HTMLElement} button - Button element to animate
 */
export function copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
        // Show success state on button
        if (button) {
            button.classList.add('copied');
            button.innerHTML = Icons.check;
            
            // Reset button after delay
            setTimeout(() => {
                button.classList.remove('copied');
                button.innerHTML = Icons.copy;
            }, 2000);
        }
        
        // Show toast notification
        showToast('Скопировано в буфер обмена');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showToast('Ошибка копирования');
    });
}

/**
 * Show a toast notification
 * @param {string} message - Message to display
 */
export function showToast(message) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    
    toast.innerHTML = `${Icons.check}<span>${escapeHtml(message)}</span>`;
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 2500);
}
