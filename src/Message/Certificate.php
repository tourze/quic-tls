<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Message;

/**
 * TLS 1.3 Certificate消息
 */
class Certificate
{
    private string $certificateRequestContext = '';
    private array $certificateList = [];

    public function __construct($certificates = null)
    {
        if (is_string($certificates)) {
            $this->certificateList = [$certificates];
        } elseif (is_array($certificates)) {
            $this->certificateList = $certificates;
        }
    }

    /**
     * 编码Certificate消息
     */
    public function encode(): string
    {
        $data = '';
        
        // Certificate Request Context
        $data .= chr(strlen($this->certificateRequestContext)) . $this->certificateRequestContext;
        
        // Certificate List
        $certificateListData = '';
        foreach ($this->certificateList as $cert) {
            // Certificate Entry
            $certificateListData .= $this->encodeCertificateEntry($cert);
        }
        
        $data .= substr(pack('N', strlen($certificateListData)), 1); // 3-byte length
        $data .= $certificateListData;
        
        return $data;
    }

    /**
     * 从二进制数据解码Certificate消息
     */
    public static function decode(string $data): self
    {
        $offset = 0;
        $certificate = new self();
        
        // Certificate Request Context
        $contextLength = ord($data[$offset]);
        $offset++;
        $certificate->certificateRequestContext = substr($data, $offset, $contextLength);
        $offset += $contextLength;
        
        // Certificate List Length
        $certificateListLength = unpack('N', "\x00" . substr($data, $offset, 3))[1];
        $offset += 3;
        
        // Parse Certificate List
        $listEnd = $offset + $certificateListLength;
        while ($offset < $listEnd) {
            $certData = self::decodeCertificateEntry($data, $offset);
            if ($certData !== null) {
                $certificate->certificateList[] = $certData;
            }
        }
        
        return $certificate;
    }

    /**
     * 编码证书条目
     */
    private function encodeCertificateEntry(string $certificate): string
    {
        $data = '';
        
        // Certificate Data Length (3 bytes)
        $data .= substr(pack('N', strlen($certificate)), 1);
        
        // Certificate Data
        $data .= $certificate;
        
        // Extensions (empty for now)
        $data .= pack('n', 0); // Extensions Length
        
        return $data;
    }

    /**
     * 解码证书条目
     */
    private static function decodeCertificateEntry(string $data, int &$offset): ?string
    {
        if ($offset + 3 > strlen($data)) {
            return null;
        }
        
        // Certificate Data Length
        $certLength = unpack('N', "\x00" . substr($data, $offset, 3))[1];
        $offset += 3;
        
        if ($offset + $certLength > strlen($data)) {
            return null;
        }
        
        // Certificate Data
        $certificate = substr($data, $offset, $certLength);
        $offset += $certLength;
        
        // Extensions Length
        if ($offset + 2 > strlen($data)) {
            return null;
        }
        
        $extensionsLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        
        // Skip Extensions
        $offset += $extensionsLength;
        
        return $certificate;
    }

    /**
     * 获取证书链
     */
    public function getCertificateChain(): array
    {
        return $this->certificateList;
    }

    /**
     * 设置证书链
     */
    public function setCertificateChain(array $certificates): void
    {
        $this->certificateList = $certificates;
    }

    /**
     * 添加证书
     */
    public function addCertificate(string $certificate): void
    {
        $this->certificateList[] = $certificate;
    }

    /**
     * 获取叶子证书
     */
    public function getLeafCertificate(): ?string
    {
        return $this->certificateList[0] ?? null;
    }

    /**
     * 设置证书请求上下文
     */
    public function setCertificateRequestContext(string $context): void
    {
        $this->certificateRequestContext = $context;
    }

    /**
     * 获取证书请求上下文
     */
    public function getCertificateRequestContext(): string
    {
        return $this->certificateRequestContext;
    }
    
    /**
     * 设置证书列表
     */
    public function setCertificates(array $certificates): void
    {
        $this->certificateList = $certificates;
    }
} 