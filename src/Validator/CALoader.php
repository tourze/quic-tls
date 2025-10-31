<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Validator;

/**
 * CA证书加载器
 *
 * 专门负责加载和管理CA证书
 */
class CALoader
{
    /** @var array<string> */
    private array $trustedCAs = [];

    /**
     * 加载系统CA证书
     */
    public function loadSystemCAs(): void
    {
        $caBundlePaths = [
            '/etc/ssl/certs/ca-certificates.crt', // Debian/Ubuntu
            '/etc/pki/tls/certs/ca-bundle.crt',   // CentOS/RHEL
            '/etc/ssl/ca-bundle.pem',             // OpenSUSE
            '/usr/local/share/certs/ca-root-nss.crt', // FreeBSD
        ];

        foreach ($caBundlePaths as $path) {
            if (file_exists($path) && is_readable($path)) {
                $this->loadCABundle($path);
                break;
            }
        }
    }

    /**
     * 加载CA证书包
     */
    private function loadCABundle(string $path): void
    {
        $caData = file_get_contents($path);
        if (false === $caData) {
            return;
        }

        $certificates = [];
        $matchCount = preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $caData, $matches);
        if ($matchCount > 0) {
            $certificates = $matches[0];
        }

        $this->trustedCAs = array_merge($this->trustedCAs, $certificates);
    }

    /**
     * 添加受信任的CA证书
     */
    public function addTrustedCA(string $caCertificate): void
    {
        $this->trustedCAs[] = $caCertificate;
    }

    /**
     * 获取受信任的CA证书列表
     */
    /**
     * @return array<string>
     */
    public function getTrustedCAs(): array
    {
        return $this->trustedCAs;
    }

    /**
     * 获取系统 CA 证书路径
     */
    public function getSystemCACertificatePath(): string
    {
        $commonPaths = [
            '/etc/ssl/certs/ca-certificates.crt',
            '/etc/pki/tls/certs/ca-bundle.crt',
            '/usr/share/ssl/certs/ca-bundle.crt',
            '/usr/local/share/certs/ca-root-nss.crt',
            '/etc/ssl/cert.pem',
        ];

        foreach ($commonPaths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return '';
    }
}
