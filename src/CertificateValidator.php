<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS;

use Tourze\QUIC\TLS\Exception\CertificateValidationException;
use Tourze\QUIC\TLS\Exception\InvalidCertificateException;
use Tourze\QUIC\TLS\Validator\CALoader;
use Tourze\QUIC\TLS\Validator\CertificateChainValidator;
use Tourze\QUIC\TLS\Validator\CertificateParser;
use Tourze\QUIC\TLS\Validator\HostnameValidator;

/**
 * 证书验证器
 *
 * 实现X.509证书验证、证书链验证和数字签名验证
 */
class CertificateValidator
{
    private ?string $serverCertificate = null;

    private ?\OpenSSLAsymmetricKey $serverPrivateKey = null;

    private bool $verifyPeer = true;

    private bool $verifyPeerName = true;

    private bool $allowSelfSigned = false;

    private int $verifyDepth = 7;

    private bool $disableCompression = true;

    private string $caFile = '';

    private bool $checkRevocation = false;

    private CertificateChainValidator $chainValidator;

    private HostnameValidator $hostnameValidator;

    private CertificateParser $parser;

    private CALoader $caLoader;

    /**
     * @param array<string, mixed> $options
     */
    public function __construct(array $options = [])
    {
        $this->serverCertificate = $options['server_cert'] ?? null;
        $this->verifyPeer = $options['verify_peer'] ?? true;
        $this->verifyPeerName = $options['verify_peer_name'] ?? true;
        $this->allowSelfSigned = $options['allow_self_signed'] ?? false;
        $this->verifyDepth = $options['verify_depth'] ?? 7;
        $this->disableCompression = $options['disable_compression'] ?? true;
        $this->checkRevocation = $options['check_revocation'] ?? false;

        $this->caLoader = new CALoader();
        if (isset($options['ca_cert'])) {
            $this->caLoader->addTrustedCA($options['ca_cert']);
        }
        $this->caFile = $options['ca_file'] ?? $this->caLoader->getSystemCACertificatePath();
        $this->caLoader->loadSystemCAs();

        $this->chainValidator = new CertificateChainValidator(
            $this->caLoader->getTrustedCAs(),
            $this->allowSelfSigned,
            $this->verifyDepth
        );
        $this->hostnameValidator = new HostnameValidator($this->verifyPeerName);
        $this->parser = new CertificateParser();

        if (isset($options['server_key'])) {
            try {
                $key = openssl_pkey_get_private($options['server_key']);
                if (false === $key) {
                    throw new InvalidCertificateException('无效的服务器私钥');
                }
                $this->serverPrivateKey = $key;
            } catch (\Throwable $e) {
                throw new InvalidCertificateException('无效的服务器私钥: ' . $e->getMessage(), previous: $e);
            }
        }
    }

    /**
     * 获取配置
     *
     * @return array<string, mixed>
     */
    public function getConfig(): array
    {
        return [
            'verify_peer' => $this->verifyPeer,
            'verify_peer_name' => $this->verifyPeerName,
            'allow_self_signed' => $this->allowSelfSigned,
            'verify_depth' => $this->verifyDepth,
            'disable_compression' => $this->disableCompression,
            'ca_file' => $this->caFile,
            'check_revocation' => $this->checkRevocation,
        ];
    }

    /**
     * 验证证书链
     *
     * @param array<int, string> $certificateChain
     */
    public function validateCertificate(array $certificateChain): bool
    {
        if (!$this->verifyPeer) {
            return true;
        }

        if ([] === $certificateChain) {
            return false;
        }

        $leafCert = $certificateChain[0];
        $certInfo = openssl_x509_parse($leafCert);
        if (false === $certInfo) {
            return false;
        }

        if (!$this->parser->checkCertificateValidity($certInfo)) {
            return false;
        }

        return $this->chainValidator->validateChain($certificateChain);
    }

    /**
     * 验证转录哈希的签名
     */
    public function verifyTranscriptSignature(string $transcriptHash, string $signature): bool
    {
        if (null === $this->serverCertificate) {
            return false;
        }

        $pubKey = openssl_pkey_get_public($this->serverCertificate);
        if (false === $pubKey) {
            return false;
        }

        // 构造TLS 1.3签名上下文
        $contextString = str_repeat(chr(0x20), 64) .
                        'TLS 1.3, server CertificateVerify' .
                        chr(0) .
                        $transcriptHash;

        return 1 === openssl_verify($contextString, $signature, $pubKey, OPENSSL_ALGO_SHA256);
    }

    /**
     * 签名转录哈希（服务器端）
     */
    public function signTranscript(string $transcriptHash): string
    {
        if (null === $this->serverPrivateKey) {
            throw new CertificateValidationException('服务器私钥未设置');
        }

        // 构造TLS 1.3签名上下文
        $contextString = str_repeat(chr(0x20), 64) .
                        'TLS 1.3, server CertificateVerify' .
                        chr(0) .
                        $transcriptHash;

        $signature = '';
        if (false === openssl_sign($contextString, $signature, $this->serverPrivateKey, OPENSSL_ALGO_SHA256)) {
            throw new CertificateValidationException('签名失败');
        }

        return $signature;
    }

    /**
     * 检查是否有服务器证书
     */
    public function hasServerCertificate(): bool
    {
        return null !== $this->serverCertificate;
    }

    /**
     * 检查是否需要证书验证
     */
    public function requiresCertificate(): bool
    {
        // 如果禁用了对等验证或允许自签名证书，就不需要完整的证书验证
        return $this->verifyPeer && !$this->allowSelfSigned;
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
    public function setServerCertificate(string $certificate, string $privateKey = ''): void
    {
        $this->serverCertificate = $certificate;
        if ('' !== $privateKey) {
            try {
                $key = openssl_pkey_get_private($privateKey);
                if (false === $key) {
                    throw new InvalidCertificateException('无效的私钥');
                }
                $this->serverPrivateKey = $key;
            } catch (\Throwable $e) {
                throw new InvalidCertificateException('无效的私钥: ' . $e->getMessage());
            }
        }
    }

    /**
     * 设置服务器私钥
     */
    public function setServerPrivateKey(string $privateKey): void
    {
        try {
            $key = openssl_pkey_get_private($privateKey);
            if (false === $key) {
                throw new InvalidCertificateException('无效的私钥');
            }
            $this->serverPrivateKey = $key;
        } catch (\Throwable $e) {
            throw new InvalidCertificateException('无效的私钥: ' . $e->getMessage());
        }
    }

    /**
     * 添加受信任的CA证书
     */
    public function addTrustedCA(string $caCertificate): void
    {
        $this->caLoader->addTrustedCA($caCertificate);
    }

    /**
     * 验证证书链的完整性
     *
     * @param array<int, string> $certificateChain
     */
    public function validateCertificateChain(array $certificateChain, ?string $hostname = null): bool
    {
        if ([] === $certificateChain) {
            return false;
        }

        if (1 === count($certificateChain)) {
            return $this->validateSingleCertificate($certificateChain[0], $hostname);
        }

        return $this->validateMultipleCertificates($certificateChain, $hostname);
    }

    /**
     * 验证单个证书
     */
    private function validateSingleCertificate(string $cert, ?string $hostname): bool
    {
        $certInfo = openssl_x509_parse($cert);
        if (false === $certInfo || !$this->parser->checkCertificateValidity($certInfo)) {
            return false;
        }

        if (!$this->verifyPeer) {
            return true;
        }

        // 对于单个证书，允许自签名证书通过验证
        $tempChainValidator = new CertificateChainValidator(
            $this->caLoader->getTrustedCAs(),
            true, // 临时允许自签名
            $this->verifyDepth
        );

        if (!$tempChainValidator->validateChain([$cert])) {
            return false;
        }

        if (null !== $hostname) {
            return $this->hostnameValidator->validateHostname($cert, $hostname);
        }

        return true;
    }

    /**
     * 验证多个证书
     *
     * @param array<int, string> $certificateChain
     */
    private function validateMultipleCertificates(array $certificateChain, ?string $hostname): bool
    {
        if ($this->parser->checkDuplicateCertificates($certificateChain)) {
            return false;
        }

        if (!$this->parser->validateAllCertificatesDates($certificateChain)) {
            return false;
        }

        if (!$this->chainValidator->validateChain($certificateChain)) {
            return false;
        }

        if (null !== $hostname) {
            return $this->hostnameValidator->validateHostname($certificateChain[0], $hostname);
        }

        return true;
    }

    /**
     * 获取证书信息
     *
     * @return array<string, mixed>
     */
    public function getCertificateInfo(string $certificate): array
    {
        return $this->parser->getCertificateInfo($certificate);
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

    /**
     * 加载系统 CA 证书
     */
    public function loadSystemCACertificates(): string
    {
        return $this->caLoader->getSystemCACertificatePath();
    }

    /**
     * 获取证书指纹
     */
    public function getCertificateFingerprint(string $certificate): string
    {
        return $this->parser->getCertificateFingerprint($certificate);
    }

    /**
     * 主机名验证
     */
    public function verifyHostname(string $certificate, string $hostname): bool
    {
        return $this->hostnameValidator->validateHostname($certificate, $hostname);
    }

    /**
     * 通配符匹配
     */
    public function matchesWildcard(string $hostname, string $pattern): bool
    {
        return $this->hostnameValidator->matchesWildcard($hostname, $pattern);
    }

    /**
     * 签名数据
     */
    public function signData(string $data, string $privateKey): string
    {
        $key = openssl_pkey_get_private($privateKey);
        if (false === $key) {
            throw new InvalidCertificateException('无效的私钥');
        }

        $signature = '';
        $result = openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256);

        if (!$result) {
            throw new CertificateValidationException('签名失败');
        }

        return $signature;
    }

    /**
     * 验证签名
     */
    public function verifySignature(string $data, string $signature, string $certificate): bool
    {
        $publicKey = openssl_pkey_get_public($certificate);
        if (false === $publicKey) {
            return false;
        }

        $result = openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        return 1 === $result;
    }
}
