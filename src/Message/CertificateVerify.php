<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Message;

/**
 * TLS 1.3 CertificateVerify消息
 */
class CertificateVerify
{
    private int $signatureAlgorithm;
    private string $signature;

    public function __construct(string $signature = '', int $algorithm = 0x0403)
    {
        $this->signature = $signature;
        $this->signatureAlgorithm = $algorithm; // 默认: ecdsa_secp256r1_sha256
    }

    /**
     * 编码CertificateVerify消息
     */
    public function encode(): string
    {
        $data = '';
        
        // Signature Algorithm
        $data .= pack('n', $this->signatureAlgorithm);
        
        // Signature
        $data .= pack('n', strlen($this->signature));
        $data .= $this->signature;
        
        return $data;
    }

    /**
     * 从二进制数据解码CertificateVerify消息
     */
    public static function decode(string $data): self
    {
        $offset = 0;
        
        // Signature Algorithm
        $algorithm = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        
        // Signature Length
        $signatureLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        
        // Signature
        $signature = substr($data, $offset, $signatureLength);
        
        return new self($signature, $algorithm);
    }

    /**
     * 获取签名
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * 设置签名
     */
    public function setSignature(string $signature): void
    {
        $this->signature = $signature;
    }

    /**
     * 获取签名算法
     */
    public function getSignatureAlgorithm(): int
    {
        return $this->signatureAlgorithm;
    }

    /**
     * 设置签名算法
     */
    public function setSignatureAlgorithm(int $algorithm): void
    {
        $this->signatureAlgorithm = $algorithm;
    }
} 