<?php
declare(strict_types=1);

/**
 * SRP Client - Smart Redirect Proxy
 * Production-ready decision routing system
 */

// Configuration
const SRP_URL = 'https://hantuin.com/api/v1/decision';
const SRP_KEY = 'c801391e6c2726eb1037d72f8b703b0eb3b0ec15a3894a16663ef69eaa1a42159';
const FALLBACK_PATH = '/meetups/redirect.php';
const API_TIMEOUT = 5;
const API_CONNECT_TIMEOUT = 3;

// Error logging function
function logError(string $message, array $context = []): void
{
    error_log(sprintf(
        '[SRP] %s | Context: %s',
        $message,
        json_encode($context, JSON_UNESCAPED_SLASHES)
    ));
}

// Build fallback URL with query string
function buildFallbackUrl(): string
{
    $query = trim((string)($_SERVER['QUERY_STRING'] ?? ''));
    $fallback = FALLBACK_PATH;
    
    if ($query !== '') {
        $fallback .= '?' . $query;
    }
    
    return $fallback;
}

// Generate or retrieve click ID
function getClickId(): string
{
    $clickId = trim((string)($_GET['click_id'] ?? ''));
    
    if ($clickId === '') {
        $clickId = 'AUTO_' . bin2hex(random_bytes(8));
    }
    
    return $clickId;
}

// Extract and validate IP address
function getClientIp(): string
{
    $rawIp = $_SERVER['HTTP_CF_CONNECTING_IP'] 
        ?? $_SERVER['HTTP_X_FORWARDED_FOR'] 
        ?? $_SERVER['REMOTE_ADDR'] 
        ?? '';
    
    $ip = filter_var(
        explode(',', (string)$rawIp)[0],
        FILTER_VALIDATE_IP
    );
    
    return $ip ?: '127.0.0.1';
}

// Get country code from headers
function getCountryCode(): string
{
    $cc = strtoupper(trim((string)(
        $_SERVER['HTTP_CF_IPCOUNTRY'] 
        ?? $_SERVER['HTTP_X_COUNTRY_CODE'] 
        ?? 'XX'
    )));
    
    // Validate country code format (2 letters)
    if (!preg_match('/^[A-Z]{2}$/', $cc)) {
        $cc = 'XX';
    }
    
    return $cc;
}

// Build API request payload
function buildPayload(string $clickId, string $cc, string $ip): string
{
    try {
        return json_encode([
            'click_id' => $clickId,
            'country_code' => $cc,
            'user_agent' => (string)($_SERVER['HTTP_USER_AGENT'] ?? ''),
            'ip_address' => $ip,
            'user_lp' => (string)($_GET['user_lp'] ?? ''),
            'referer' => (string)($_SERVER['HTTP_REFERER'] ?? ''),
            'timestamp' => time(),
        ], JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    } catch (\Throwable $e) {
        logError('Failed to encode payload', ['error' => $e->getMessage()]);
        throw $e;
    }
}

// Make API request to decision endpoint
function makeDecisionRequest(string $payload): ?array
{
    $ch = curl_init(SRP_URL);
    
    if ($ch === false) {
        logError('Failed to initialize cURL');
        return null;
    }
    
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => API_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => API_CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-API-Key: ' . SRP_KEY,
            'X-Request-ID: ' . bin2hex(random_bytes(16)),
            'Accept: application/json',
        ],
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_USERAGENT => 'SRP-Client/2.0',
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS => 0,
    ]);
    
    try {
        $body = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        
        if ($body === false) {
            logError('cURL execution failed', [
                'error' => $curlError,
                'errno' => curl_errno($ch)
            ]);
            return null;
        }
        
        if ($httpCode !== 200) {
            logError('API returned non-200 status', [
                'status' => $httpCode,
                'body' => substr((string)$body, 0, 200)
            ]);
            return null;
        }
        
        $response = json_decode((string)$body, true, 512, JSON_THROW_ON_ERROR);
        
        if (!is_array($response)) {
            logError('Invalid API response format');
            return null;
        }
        
        return $response;
        
    } catch (\Throwable $e) {
        logError('Request processing failed', [
            'error' => $e->getMessage(),
            'type' => get_class($e)
        ]);
        return null;
    } finally {
        curl_close($ch);
    }
}

// Process API response and determine target URL
function processDecision(?array $response, string $fallback): string
{
    if ($response === null) {
        return $fallback;
    }
    
    // Check if decision is valid
    if (!($response['ok'] ?? false)) {
        logError('API returned ok=false', ['response' => $response]);
        return $fallback;
    }
    
    $decision = $response['decision'] ?? 'B';
    
    if ($decision !== 'A') {
        return $fallback;
    }
    
    $target = $response['target'] ?? '';
    
    // Validate target URL
    if (!filter_var($target, FILTER_VALIDATE_URL)) {
        logError('Invalid target URL', ['target' => $target]);
        return $fallback;
    }
    
    // Additional security: ensure HTTPS for external redirects
    $parsedUrl = parse_url($target);
    if (($parsedUrl['scheme'] ?? '') !== 'https' && ($parsedUrl['scheme'] ?? '') !== 'http') {
        logError('Invalid URL scheme', ['target' => $target]);
        return $fallback;
    }
    
    return (string)$target;
}

// Set security headers
function setSecurityHeaders(): void
{
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0', true);
    header('Pragma: no-cache', true);
    header('Expires: 0', true);
    header('X-Content-Type-Options: nosniff', true);
    header('X-Frame-Options: DENY', true);
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'", true);
    header('Referrer-Policy: no-referrer', true);
    header('X-XSS-Protection: 1; mode=block', true);
    
    // HSTS for HTTPS connections
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload', true);
    }
}

// Sanitize redirect target to prevent header injection
function sanitizeRedirectTarget(string $target): string
{
    return str_replace(["\r", "\n", "\t", "\0", "\x0B"], '', $target);
}

// Perform redirect
function performRedirect(string $target): void
{
    $cleanTarget = sanitizeRedirectTarget($target);
    
    // Additional validation after sanitization
    if ($cleanTarget === '') {
        logError('Empty target after sanitization');
        $cleanTarget = FALLBACK_PATH;
    }
    
    header('Location: ' . $cleanTarget, true, 302);
    exit(0);
}

// Main execution
try {
    // Initialize
    $fallback = buildFallbackUrl();
    $clickId = getClickId();
    $ip = getClientIp();
    $cc = getCountryCode();
    
    // Build and send request
    $payload = buildPayload($clickId, $cc, $ip);
    $response = makeDecisionRequest($payload);
    
    // Process decision
    $target = processDecision($response, $fallback);
    
    // Set headers and redirect
    setSecurityHeaders();
    performRedirect($target);
    
} catch (\Throwable $e) {
    // Catastrophic error - log and redirect to fallback
    logError('Fatal error in main execution', [
        'error' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine(),
        'trace' => $e->getTraceAsString()
    ]);
    
    setSecurityHeaders();
    performRedirect(buildFallbackUrl());
}
