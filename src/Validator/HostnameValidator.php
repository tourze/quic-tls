<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Validator;

/**
 * 主机名验证器
 *
 * 专门负责主机名验证逻辑
 */
class HostnameValidator
{
    public function __construct(private readonly bool $verifyPeerName = true)
    {
    }

    /**
     * 验证证书的主机名
     */
    public function validateHostname(string $certificate, string $hostname): bool
    {
        if (!$this->verifyPeerName) {
            return true;
        }

        $certInfo = openssl_x509_parse($certificate);
        if (false === $certInfo) {
            return false;
        }

        return $this->checkCommonName($certInfo, $hostname)
               || $this->checkSubjectAltName($certInfo, $hostname);
    }

    /**
     * 检查CN字段
     *
     * @param array<string, mixed> $certInfo
     */
    private function checkCommonName(array $certInfo, string $hostname): bool
    {
        if (!isset($certInfo['subject']['CN'])) {
            return false;
        }

        return $this->matchHostname($certInfo['subject']['CN'], $hostname);
    }

    /**
     * 检查SAN扩展
     *
     * @param array<string, mixed> $certInfo
     */
    private function checkSubjectAltName(array $certInfo, string $hostname): bool
    {
        if (!isset($certInfo['extensions']['subjectAltName'])) {
            return false;
        }

        $sanList = explode(',', $certInfo['extensions']['subjectAltName']);
        foreach ($sanList as $san) {
            $san = trim($san);
            if (0 === strpos($san, 'DNS:')) {
                $dnsName = substr($san, 4);
                if ($this->matchHostname($dnsName, $hostname)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 匹配主机名（支持通配符）
     */
    private function matchHostname(string $pattern, string $hostname): bool
    {
        if (false !== strpos($pattern, '*')) {
            $regex = '/^' . str_replace(['*', '.'], ['[^.]*', '\.'], $pattern) . '$/i';

            return 1 === preg_match($regex, $hostname);
        }

        return 0 === strcasecmp($pattern, $hostname);
    }

    /**
     * 通配符匹配
     */
    public function matchesWildcard(string $hostname, string $pattern): bool
    {
        return $this->matchHostname($pattern, $hostname);
    }
}
