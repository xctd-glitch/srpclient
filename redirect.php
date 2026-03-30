<?php

declare(strict_types=1);

namespace App;

final class RedirectHandler
{
    private const API_URL = 'https://hantuin.com/api/v1/decision';
    private const API_KEY = 'c801391e6c2726eb1037d72f8b703b0eb3b0ec15a3894a16663ef69eaa1a42159';
    private const DEFAULT_FALLBACK = '/meetups/redirect.php';
    private const TIMEOUT = 5;
    private const CONNECT_TIMEOUT = 3;
    private const MAX_RETRIES = 2;

    private string $fallback;
    private string $clickId;
    private string $ip;
    private string $countryCode;
    private string $userAgent;
    private string $userLp;

    public function __construct()
    {
        $this->fallback = self::DEFAULT_FALLBACK;
        $this->initializeFromRequest();
    }

    private function initializeFromRequest(): void
    {
        $query = trim((string)($this->getServerVar('QUERY_STRING') ?? ''));
        if ($query !== '') {
            $this->fallback .= '?' . $this->sanitizeQueryString($query);
        }

        $this->clickId = $this->getClickId();
        $this->ip = $this->detectClientIp();
        $this->countryCode = $this->detectCountryCode();
        $this->userAgent = $this->getServerVar('HTTP_USER_AGENT') ?? '';
        $this->userLp = $this->getServerVar('user_lp') ?? '';
    }

    private function getClickId(): string
    {
        $clickId = $this->getServerVar('click_id') ?? '';
        if ($clickId !== '') {
            return $this->sanitizeClickId($clickId);
        }
        return 'AUTO_' . bin2hex(random_bytes(4));
    }

    private function sanitizeClickId(string $clickId): string
    {
        return preg_replace('/[^a-zA-Z0-9_-]/', '', $clickId) ?: '';
    }

    private function sanitizeQueryString(string $query): string
    {
        return preg_replace('/[^\w\d&=%.-]/', '', $query) ?: '';
    }

    private function detectClientIp(): string
    {
        $rawIp = $this->getServerVar('HTTP_CF_CONNECTING_IP')
            ?? $this->getServerVar('HTTP_X_FORWARDED_FOR')
            ?? $this->getServerVar('REMOTE_ADDR')
            ?? '127.0.0.1';

        $ip = explode(',', (string)$rawIp)[0];
        $validated = filter_var(trim($ip), FILTER_VALIDATE_IP);

        return $validated ?: '127.0.0.1';
    }

    private function detectCountryCode(): string
    {
        $cc = $this->getServerVar('HTTP_CF_IPCOUNTRY')
            ?? $this->getServerVar('HTTP_X_COUNTRY_CODE')
            ?? 'XX';

        return strtoupper(trim(substr((string)$cc, 0, 2)));
    }

    private function getServerVar(string $name): ?string
    {
        return $_GET[$name] ?? ($_SERVER[$name] ?? null);
    }

    public function execute(): void
    {
        $this->setSecurityHeaders();

        $target = $this->determineRedirectTarget();

        $this->sendRedirect($target);
    }

    private function determineRedirectTarget(): string
    {
        $payload = $this->buildPayload();

        for ($attempt = 0; $attempt <= self::MAX_RETRIES; $attempt++) {
            try {
                $response = $this->callApi($payload);
                $target = $this->parseApiResponse($response);

                if ($target !== null) {
                    return $target;
                }
            } catch (\Throwable $e) {
                $this->logError('API call failed', [
                    'attempt' => $attempt + 1,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        return $this->fallback;
    }

    private function buildPayload(): array
    {
        return [
            'click_id' => $this->clickId,
            'country_code' => $this->countryCode,
            'user_agent' => $this->userAgent,
            'ip_address' => $this->ip,
            'user_lp' => $this->userLp,
        ];
    }

    private function callApi(array $payload): string
    {
        $ch = curl_init();

        if ($ch === false) {
            throw new \RuntimeException('Failed to initialize cURL');
        }

        try {
            $jsonPayload = json_encode($payload, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);

            curl_setopt_array($ch, [
                CURLOPT_URL => self::API_URL,
                CURLOPT_POST => true,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => self::TIMEOUT,
                CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/json',
                    'X-API-Key: ' . self::API_KEY,
                    'X-Request-ID: ' . bin2hex(random_bytes(8)),
                ],
                CURLOPT_POSTFIELDS => $jsonPayload,
            ]);

            $body = curl_exec($ch);
            $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

            if ($body === false) {
                $error = curl_error($ch);
                $errno = curl_errno($ch);
                throw new \RuntimeException("cURL error: {$error} ({$errno})");
            }

            if ($httpCode !== 200) {
                throw new \RuntimeException("HTTP error: {$httpCode}");
            }

            return $body;
        } finally {
            curl_close($ch);
        }
    }

    private function parseApiResponse(string $response): ?string
    {
        try {
            $data = json_decode($response, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $this->logError('JSON decode failed', ['error' => $e->getMessage()]);
            return null;
        }

        if (!($data['ok'] ?? false)) {
            $this->logError('API response not ok', ['response' => $data]);
            return null;
        }

        if (($data['decision'] ?? 'B') !== 'A') {
            return null;
        }

        $target = $data['target'] ?? '';
        if (!filter_var($target, FILTER_VALIDATE_URL)) {
            $this->logError('Invalid target URL', ['target' => $target]);
            return null;
        }

        return (string)$target;
    }

    private function setSecurityHeaders(): void
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

    private function sendRedirect(string $target): never
    {
        $cleanTarget = $this->sanitizeRedirectUrl($target);

        http_response_code(302);
        header('Location: ' . $cleanTarget, true, 302);
        exit;
    }

    private function sanitizeRedirectUrl(string $url): string
    {
        return str_replace(["\r", "\n", "\t", "\0", "\x0B"], '', $url);
    }

    private function logError(string $message, array $context = []): void
    {
        error_log(sprintf(
            '[%s] %s | ClickID: %s | IP: %s | Context: %s',
            date('Y-m-d H:i:s'),
            $message,
            $this->clickId,
            $this->ip,
            json_encode($context)
        ));
    }
}

(new RedirectHandler())->execute();
