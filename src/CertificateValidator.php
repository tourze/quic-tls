<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS;

use OpenSSLAsymmetricKey;

/**
 * 证书验证器
 * 
 * 实现X.509证书验证、证书链验证和数字签名验证
 */
class CertificateValidator
{
    private ?string $serverCertificate = null;
    private ?OpenSSLAsymmetricKey $serverPrivateKey = null;
    private ?string $caCertificate = null;
    private array $trustedCAs = [];
    private bool $verifyPeer = true;
    private bool $allowSelfSigned = false;
    private int $verifyDepth = 9;

    public function __construct(array $options = [])
    {
        $this->serverCertificate = $options['server_cert'] ?? null;
        $this->caCertificate = $options['ca_cert'] ?? null;
        $this->verifyPeer = $options['verify_peer'] ?? true;
        $this->allowSelfSigned = $options['allow_self_signed'] ?? false;
        $this->verifyDepth = $options['verify_depth'] ?? 9;
        
        if (isset($options['server_key'])) {
            $this->serverPrivateKey = openssl_pkey_get_private($options['server_key']);
            if ($this->serverPrivateKey === false) {
                throw new \InvalidArgumentException('无效的服务器私钥');
            }
        }
        
        $this->loadSystemCAs();
    }

    /**
     * 验证证书链
     */
    public function validateCertificate(array $certificateChain): bool
    {
        if (empty($certificateChain)) {
            return false;
        }

        $leafCert = $certificateChain[0];
        
        // 解析叶子证书
        $certInfo = openssl_x509_parse($leafCert);
        if ($certInfo === false) {
            return false;
        }

        // 检查证书有效期
        if (!$this->checkCertificateValidity($certInfo)) {
            return false;
        }

        // 如果不需要对等验证，只验证格式
        if (!$this->verifyPeer) {
            return true;
        }

        // 验证证书链
        return $this->verifyCertificateChain($certificateChain);
    }

    /**
     * 验证证书链
     */
    private function verifyCertificateChain(array $certificateChain): bool
    {
        $chainLength = count($certificateChain);
        
        if ($chainLength > $this->verifyDepth) {
            return false;
        }

        // 如果只有一个证书且允许自签名
        if ($chainLength === 1 && $this->allowSelfSigned) {
            return $this->verifySelfSignedCertificate($certificateChain[0]);
        }

        // 验证链中每个证书
        for ($i = 0; $i < $chainLength - 1; $i++) {
            $currentCert = $certificateChain[$i];
            $issuerCert = $certificateChain[$i + 1];
            
            if (!$this->verifyCertificateSignature($currentCert, $issuerCert)) {
                return false;
            }
        }

        // 验证根证书
        $rootCert = $certificateChain[$chainLength - 1];
        return $this->verifyRootCertificate($rootCert);
    }

    /**
     * 验证证书签名
     */
    private function verifyCertificateSignature(string $cert, string $issuerCert): bool
    {
        $pubKey = openssl_pkey_get_public($issuerCert);
        if ($pubKey === false) {
            return false;
        }

        $result = openssl_x509_verify($cert, $pubKey);
        
        return $result === 1;
    }

    /**
     * 验证自签名证书
     */
    private function verifySelfSignedCertificate(string $cert): bool
    {
        $pubKey = openssl_pkey_get_public($cert);
        if ($pubKey === false) {
            return false;
        }

        return openssl_x509_verify($cert, $pubKey) === 1;
    }

    /**
     * 验证根证书
     */
    private function verifyRootCertificate(string $rootCert): bool
    {
        // 检查是否在受信任的CA列表中
        foreach ($this->trustedCAs as $trustedCA) {
            if ($this->compareCertificates($rootCert, $trustedCA)) {
                return true;
            }
        }

        // 检查是否为自签名的根证书
        return $this->verifySelfSignedCertificate($rootCert);
    }

    /**
     * 比较两个证书是否相同
     */
    private function compareCertificates(string $cert1, string $cert2): bool
    {
        $fingerprint1 = openssl_x509_fingerprint($cert1, 'sha256');
        $fingerprint2 = openssl_x509_fingerprint($cert2, 'sha256');
        
        return $fingerprint1 === $fingerprint2;
    }

    /**
     * 检查证书有效期
     */
    private function checkCertificateValidity(array $certInfo): bool
    {
        $now = time();
        
        // 检查证书是否已过期
        if (isset($certInfo['validTo_time_t']) && $certInfo['validTo_time_t'] < $now) {
            return false;
        }
        
        // 检查证书是否还未生效
        if (isset($certInfo['validFrom_time_t']) && $certInfo['validFrom_time_t'] > $now) {
            return false;
        }
        
        return true;
    }

    /**
     * 验证转录哈希的签名
     */
    public function verifyTranscriptSignature(string $transcriptHash, string $signature): bool
    {
        if ($this->serverCertificate === null) {
            return false;
        }

        $pubKey = openssl_pkey_get_public($this->serverCertificate);
        if ($pubKey === false) {
            return false;
        }

        // 构造TLS 1.3签名上下文
        $contextString = str_repeat(chr(0x20), 64) . 
                        "TLS 1.3, server CertificateVerify" . 
                        chr(0) . 
                        $transcriptHash;

        return openssl_verify($contextString, $signature, $pubKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * 签名转录哈希（服务器端）
     */
    public function signTranscript(string $transcriptHash): string
    {
        if ($this->serverPrivateKey === null) {
            throw new \RuntimeException('服务器私钥未设置');
        }

        // 构造TLS 1.3签名上下文
        $contextString = str_repeat(chr(0x20), 64) . 
                        "TLS 1.3, server CertificateVerify" . 
                        chr(0) . 
                        $transcriptHash;

        $signature = '';
        if (openssl_sign($contextString, $signature, $this->serverPrivateKey, OPENSSL_ALGO_SHA256) === false) {
            throw new \RuntimeException('签名失败');
        }

        return $signature;
    }

    /**
     * 检查是否有服务器证书
     */
    public function hasServerCertificate(): bool
    {
        return $this->serverCertificate !== null;
    }

    /**
     * 获取服务器证书
     */
    public function getServerCertificate(): ?string
    {
        return $this->serverCertificate;
    }

    /**
     * 设置服务器证书
     */
    public function setServerCertificate(string $certificate): void
    {
        $this->serverCertificate = $certificate;
    }

    /**
     * 设置服务器私钥
     */
    public function setServerPrivateKey(string $privateKey): void
    {
        $this->serverPrivateKey = openssl_pkey_get_private($privateKey);
        if ($this->serverPrivateKey === false) {
            throw new \InvalidArgumentException('无效的私钥');
        }
    }

    /**
     * 添加受信任的CA证书
     */
    public function addTrustedCA(string $caCertificate): void
    {
        $this->trustedCAs[] = $caCertificate;
    }

    /**
     * 加载系统CA证书
     */
    private function loadSystemCAs(): void
    {
        // 尝试加载系统CA包
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
        if ($caData === false) {
            return;
        }

        // 解析PEM格式的CA证书包
        $certificates = [];
        if (preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $caData, $matches)) {
            $certificates = $matches[0];
        }

        $this->trustedCAs = array_merge($this->trustedCAs, $certificates);
    }

    /**
     * 验证证书链的完整性
     */
    public function validateCertificateChain(array $certificateChain, string $hostname = null): bool
    {
        if (!$this->validateCertificate($certificateChain)) {
            return false;
        }

        // 验证主机名（如果提供）
        if ($hostname !== null) {
            return $this->validateHostname($certificateChain[0], $hostname);
        }

        return true;
    }

    /**
     * 验证证书的主机名
     */
    private function validateHostname(string $certificate, string $hostname): bool
    {
        $certInfo = openssl_x509_parse($certificate);
        if ($certInfo === false) {
            return false;
        }

        // 检查CN字段
        if (isset($certInfo['subject']['CN'])) {
            if ($this->matchHostname($certInfo['subject']['CN'], $hostname)) {
                return true;
            }
        }

        // 检查SAN扩展
        if (isset($certInfo['extensions']['subjectAltName'])) {
            $sanList = explode(',', $certInfo['extensions']['subjectAltName']);
            foreach ($sanList as $san) {
                $san = trim($san);
                if (strpos($san, 'DNS:') === 0) {
                    $dnsName = substr($san, 4);
                    if ($this->matchHostname($dnsName, $hostname)) {
                        return true;
                    }
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
        // 如果模式包含通配符
        if (strpos($pattern, '*') !== false) {
            // 转换为正则表达式
            $regex = '/^' . str_replace(['*', '.'], ['[^.]*', '\.'], $pattern) . '$/i';
            return preg_match($regex, $hostname) === 1;
        }

        // 精确匹配
        return strcasecmp($pattern, $hostname) === 0;
    }

    /**
     * 获取证书信息
     */
    public function getCertificateInfo(string $certificate): array
    {
        $info = openssl_x509_parse($certificate);
        if ($info === false) {
            throw new \InvalidArgumentException('无法解析证书');
        }

        return $info;
    }

    /**
     * 检查证书是否被吊销（简化实现）
     */
    public function isRevoked(string $certificate): bool
    {
        // 这里应该实现CRL或OCSP检查
        // 简化实现，总是返回false
        return false;
    }
} 