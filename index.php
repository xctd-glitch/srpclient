<?php
declare(strict_types=1);

$srpUrl = 'https://hantuin.com/api/v1/decision';
$srpKey = 'c801391e6c2726eb1037d72f8b703b0eb3b0ec15a3894a16663ef69eaa1a42159';
$fallback = '/meetups/redirect.php';

$query = trim((string)($_SERVER['QUERY_STRING'] ?? ''));
if ($query !== '') {
    $fallback .= '?' . $query;
}

$clickId = trim((string)($_GET['click_id'] ?? ''));
if ($clickId === '') {
    $clickId = 'AUTO_' . bin2hex(random_bytes(4));
}

$rawIp = $_SERVER['HTTP_CF_CONNECTING_IP']
    ?? $_SERVER['HTTP_X_FORWARDED_FOR']
    ?? $_SERVER['REMOTE_ADDR']
    ?? '';
$ip = filter_var(explode(',', (string)$rawIp)[0], FILTER_VALIDATE_IP) ?: '127.0.0.1';

$cc = strtoupper(trim((string)($_SERVER['HTTP_CF_IPCOUNTRY'] ?? $_SERVER['HTTP_X_COUNTRY_CODE'] ?? 'XX')));

$payload = json_encode(
    [
        'click_id' => $clickId,
        'country_code' => $cc,
        'user_agent' => (string)($_SERVER['HTTP_USER_AGENT'] ?? ''),
        'ip_address' => $ip,
        'user_lp' => (string)($_GET['user_lp'] ?? ''),
    ],
    JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR
);

$target = $fallback;

$ch = curl_init($srpUrl);
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 5,
    CURLOPT_CONNECTTIMEOUT => 3,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_HTTPHEADER => [
        'Content-Type: application/json',
        'X-API-Key: ' . $srpKey,
        'X-Request-ID: ' . bin2hex(random_bytes(8)),
    ],
    CURLOPT_POSTFIELDS => $payload,
]);

try {
    $body = curl_exec($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($body !== false && $httpCode === 200) {
        $res = json_decode((string)$body, true, 512, JSON_THROW_ON_ERROR);
        if (($res['ok'] ?? false) && ($res['decision'] ?? 'B') === 'A' && filter_var($res['target'] ?? '', FILTER_VALIDATE_URL)) {
            $target = (string)$res['target'];
        }
    }
} catch (Throwable $e) {
    $target = $fallback;
} finally {
    curl_close($ch);
}

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
header('Referrer-Policy: no-referrer');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

$cleanTarget = str_replace(["\r", "\n", "\t", "\0"], '', $target);
header('Location: ' . $cleanTarget, true, 302);
exit;
