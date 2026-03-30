<?php
declare(strict_types=1);

/**
 * SRP Decision Router - Production Version
 * Routes traffic based on SRP API decision with fallback handling
 */

// Configuration
const SRP_URL = 'https://hantuin.com/api/v1/decision';
const SRP_API_KEY = 'c801391e6c2726eb1037d72f8b703b0eb3b0ec15a3894a16663ef69eaa1a42159';
const FALLBACK_PATH = '/meetups/redirect.php';
const REQUEST_TIMEOUT = 5;
const CONNECT_TIMEOUT = 3;

/**
 * Get client IP address from various sources
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
function getSrpDecision(string $clickId, string $countryCode, string $ip): ?array
{
    $payload = json_encode([
        'click_id' => $clickId,
        'country_code' => $countryCode,
        'user_agent' => (string)($_SERVER['HTTP_USER_AGENT'] ?? ''),
        'ip_address' => $ip,
        'user_lp' => (string)($_GET['user_lp'] ?? ''),
    ], JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);

    $ch = curl_init(SRP_URL);

    if ($ch === false) {
        return null;
    }

    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => REQUEST_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-API-Key: ' . SRP_API_KEY,
            'X-Request-ID: ' . bin2hex(random_bytes(8)),
        ],
        CURLOPT_POSTFIELDS => $payload,
    ]);

    try {
        $body = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($body !== false && $httpCode === 200) {
            $response = json_decode((string)$body, true, 512, JSON_THROW_ON_ERROR);
            return is_array($response) ? $response : null;
        }
    } catch (\Throwable $e) {
        // Log error in production: error_log($e->getMessage());
        return null;
    } finally {
        curl_close($ch);
    }

    return null;
}

/**
 * Determine target URL from SRP response
 */
function getTargetUrl(?array $srpResponse, string $fallback): string
{
    if ($srpResponse === null) {
        return $fallback;
    }

    $isOk = ($srpResponse['ok'] ?? false) === true;
    $isDecisionA = ($srpResponse['decision'] ?? 'B') === 'A';
    $targetUrl = $srpResponse['target'] ?? '';
    $isValidUrl = filter_var($targetUrl, FILTER_VALIDATE_URL) !== false;

    if ($isOk && $isDecisionA && $isValidUrl) {
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
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
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
    $clickId = getClickId();
    $countryCode = getCountryCode();
    $ip = getClientIp();
    $fallback = buildFallbackUrl();

    $srpResponse = getSrpDecision($clickId, $countryCode, $ip);
    $target = getTargetUrl($srpResponse, $fallback);

    setSecurityHeaders();

    $cleanTarget = sanitizeRedirectTarget($target);
    header('Location: ' . $cleanTarget, true, 302);
}

// Execute
main();
exit;
