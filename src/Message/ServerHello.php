<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Message;

use Tourze\QUIC\TLS\TransportParameters;

/**
 * TLS 1.3 ServerHello消息
 */
class ServerHello
{
    private string $protocolVersion = "\x03\x04"; // TLS 1.3
    private string $random;
    private string $sessionId;
    private int $cipherSuite = 0x1301; // TLS_AES_128_GCM_SHA256
    private int $compressionMethod = 0x00; // null compression
    private array $extensions = [];
    private ?TransportParameters $transportParameters = null;

    public function __construct(?TransportParameters $transportParams = null)
    {
        $this->random = random_bytes(32);
        $this->sessionId = random_bytes(32);
        $this->transportParameters = $transportParams ?? new TransportParameters();
        $this->buildExtensions();
    }

    /**
     * 编码ServerHello消息
     */
    public function encode(): string
    {
        $data = '';
        
        // Protocol Version
        $data .= $this->protocolVersion;
        
        // Random
        $data .= $this->random;
        
        // Session ID
        $data .= chr(strlen($this->sessionId)) . $this->sessionId;
        
        // Cipher Suite
        $data .= pack('n', $this->cipherSuite);
        
        // Compression Method
        $data .= chr($this->compressionMethod);
        
        // Extensions
        $extensionsData = $this->encodeExtensions();
        $data .= pack('n', strlen($extensionsData)) . $extensionsData;
        
        return $data;
    }

    /**
     * 从二进制数据解码ServerHello消息
     */
    public static function decode(string $data): self
    {
        $offset = 0;
        $serverHello = new self();
        
        // Protocol Version
        $serverHello->protocolVersion = substr($data, $offset, 2);
        $offset += 2;
        
        // Random
        $serverHello->random = substr($data, $offset, 32);
        $offset += 32;
        
        // Session ID
        $sessionIdLength = ord($data[$offset]);
        $offset++;
        $serverHello->sessionId = substr($data, $offset, $sessionIdLength);
        $offset += $sessionIdLength;
        
        // Cipher Suite
        $serverHello->cipherSuite = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        
        // Compression Method
        $serverHello->compressionMethod = ord($data[$offset]);
        $offset++;
        
        // Extensions
        if ($offset < strlen($data)) {
            $extensionsLength = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;
            $serverHello->parseExtensions(substr($data, $offset, $extensionsLength));
        }
        
        return $serverHello;
    }

    /**
     * 构建扩展
     */
    private function buildExtensions(): void
    {
        // Supported Versions
        $this->extensions[0x002b] = $this->buildSupportedVersionsExtension();
        
        // Key Share
        $this->extensions[0x0033] = $this->buildKeyShareExtension();
        
        // QUIC Transport Parameters
        $this->extensions[0x0039] = $this->transportParameters->encode();
    }

    /**
     * 编码扩展
     */
    private function encodeExtensions(): string
    {
        $data = '';
        
        foreach ($this->extensions as $type => $extensionData) {
            $data .= pack('n', $type);
            $data .= pack('n', strlen($extensionData));
            $data .= $extensionData;
        }
        
        return $data;
    }

    /**
     * 解析扩展
     */
    private function parseExtensions(string $data): void
    {
        $offset = 0;
        $length = strlen($data);
        
        while ($offset < $length) {
            $type = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;
            
            $extLength = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;
            
            $extData = substr($data, $offset, $extLength);
            $offset += $extLength;
            
            $this->extensions[$type] = $extData;
            
            // 解析QUIC传输参数
            if ($type === 0x0039) {
                $this->transportParameters = TransportParameters::decode($extData);
            }
        }
    }

    /**
     * 构建支持的版本扩展
     */
    private function buildSupportedVersionsExtension(): string
    {
        return pack('n', 0x0304); // TLS 1.3
    }

    /**
     * 构建密钥共享扩展
     */
    private function buildKeyShareExtension(): string
    {
        // 生成x25519密钥对
        $privateKey = random_bytes(32);
        $publicKey = $this->generateX25519PublicKey($privateKey);
        
        $data = pack('n', 0x001d); // Named Group: x25519
        $data .= pack('n', strlen($publicKey)); // Key Exchange Length
        $data .= $publicKey;
        
        return $data;
    }

    /**
     * 生成x25519公钥（简化实现）
     */
    private function generateX25519PublicKey(string $privateKey): string
    {
        return random_bytes(32);
    }

    /**
     * 获取传输参数
     */
    public function getTransportParameters(): ?TransportParameters
    {
        return $this->transportParameters;
    }

    /**
     * 设置传输参数
     */
    public function setTransportParameters(TransportParameters $params): void
    {
        $this->transportParameters = $params;
        $this->extensions[0x0039] = $params->encode();
    }

    /**
     * 获取密码套件
     */
    public function getCipherSuite(): int
    {
        return $this->cipherSuite;
    }

    /**
     * 设置密码套件
     */
    public function setCipherSuite(int $suite): void
    {
        $this->cipherSuite = $suite;
    }
}
