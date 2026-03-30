<?php
declare(strict_types=1);

/**
 * Smart Redirect Proxy (SRP)
 * Production-ready redirect handler with API decision logic
 */

// Configuration
const SRP_URL = 'https://hantuin.com/api/v1/decision';
const SRP_KEY = 'c801391e6c2726eb1037d72f8b703b0eb3b0ec15a3894a16663ef69eaa1a42159';
const FALLBACK_PATH = '/meetups/redirect.php';
const API_TIMEOUT = 5;
const API_CONNECT_TIMEOUT = 3;

/**
 * Get client IP address from various headers
 */
function getClientIp(): string
{
    $rawIp = $_SERVER['HTTP_CF_CONNECTING_IP'] 
        ?? $_SERVER['HTTP_X_FORWARDED_FOR'] 
        ?? $_SERVER['REMOTE_ADDR'] 
        ?? '';
    
    $ipParts = explode(',', (string)$rawIp);
    $ip = filter_var(trim($ipParts[0]), FILTER_VALIDATE_IP);
    
    return $ip !== false ? $ip : '127.0.0.1';
}

/**
 * Get country code from headers
 */
function getCountryCode(): string
{
    $cc = $_SERVER['HTTP_CF_IPCOUNTRY'] 
        ?? $_SERVER['HTTP_X_COUNTRY_CODE'] 
        ?? 'XX';
    
    return strtoupper(trim((string)$cc));
}

/**
 * Generate or retrieve click ID
 */
function getClickId(): string
{
    $clickId = trim((string)($_GET['click_id'] ?? ''));
    
    if ($clickId === '') {
        $clickId = 'AUTO_' . bin2hex(random_bytes(4));
    }
    
    return $clickId;
}

/**
 * Build fallback URL with query string
 */
function buildFallbackUrl(): string
{
    $fallback = FALLBACK_PATH;
    $query = trim((string)($_SERVER['QUERY_STRING'] ?? ''));
    
    if ($query !== '') {
        $fallback .= '?' . $query;
    }
    
    return $fallback;
}

/**
 * Make API request to SRP service
 */
function makeApiRequest(array $payload): ?array
{
    $ch = curl_init(SRP_URL);
    
    if ($ch === false) {
        return null;
    }
    
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => API_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => API_CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-API-Key: ' . SRP_KEY,
            'X-Request-ID: ' . bin2hex(random_bytes(8)),
        ],
        CURLOPT_POSTFIELDS => json_encode($payload, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR),
    ]);
    
    try {
        $body = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if ($body === false || $httpCode !== 200) {
            return null;
        }
        
        $response = json_decode((string)$body, true, 512, JSON_THROW_ON_ERROR);
        
        return is_array($response) ? $response : null;
        
    } catch (\Throwable $e) {
        error_log('SRP API Error: ' . $e->getMessage());
        return null;
    } finally {
        curl_close($ch);
    }
}

/**
 * Determine redirect target based on API response
 */
function getRedirectTarget(array $payload, string $fallback): string
{
    $response = makeApiRequest($payload);
    
    if ($response === null) {
        return $fallback;
    }
    
    $isOk = ($response['ok'] ?? false) === true;
    $isDecisionA = ($response['decision'] ?? 'B') === 'A';
    $targetUrl = $response['target'] ?? '';
    
    if ($isOk && $isDecisionA && filter_var($targetUrl, FILTER_VALIDATE_URL) !== false) {
        return (string)$targetUrl;
    }
    
    return $fallback;
}

/**
 * Set security headers
 */
function setSecurityHeaders(): void
{
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    header('Referrer-Policy: no-referrer');
    
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

/**
 * Sanitize redirect target to prevent header injection
 */
function sanitizeRedirectTarget(string $target): string
{
    return str_replace(["\r", "\n", "\t", "\0"], '', $target);
}

/**
 * Main execution
 */
function main(): void
{
    // Build payload for API request
    $payload = [
        'click_id' => getClickId(),
        'country_code' => getCountryCode(),
        'user_agent' => (string)($_SERVER['HTTP_USER_AGENT'] ?? ''),
        'ip_address' => getClientIp(),
        'user_lp' => (string)($_GET['user_lp'] ?? ''),
    ];
    
    // Determine redirect target
    $fallback = buildFallbackUrl();
    $target = getRedirectTarget($payload, $fallback);
    
    // Set security headers
    setSecurityHeaders();
    
    // Perform redirect
    $cleanTarget = sanitizeRedirectTarget($target);
    header('Location: ' . $cleanTarget, true, 302);
    exit;
}

// Execute
main();
