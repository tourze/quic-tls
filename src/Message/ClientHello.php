<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Message;

use Tourze\QUIC\TLS\Exception\InvalidParameterException;

use Tourze\QUIC\TLS\TransportParameters;

/**
 * TLS 1.3 ClientHello消息
 */
class ClientHello
{
    private string $protocolVersion = "\x03\x04"; // TLS 1.3
    private string $random;
    private string $sessionId;
    private array $cipherSuites = [
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
    ];
    private array $compressionMethods = [0x00]; // null compression
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
     * 编码ClientHello消息
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
        
        // Cipher Suites
        $cipherSuitesData = '';
        foreach ($this->cipherSuites as $suite) {
            $cipherSuitesData .= pack('n', $suite);
        }
        $data .= pack('n', strlen($cipherSuitesData)) . $cipherSuitesData;
        
        // Compression Methods
        $compressionData = '';
        foreach ($this->compressionMethods as $method) {
            $compressionData .= chr($method);
        }
        $data .= chr(strlen($compressionData)) . $compressionData;
        
        // Extensions
        $extensionsData = $this->encodeExtensions();
        $data .= pack('n', strlen($extensionsData)) . $extensionsData;
        
        return $data;
    }

    /**
     * 从二进制数据解码ClientHello消息
     */
    public static function decode(string $data): self
    {
        $offset = 0;
        $clientHello = new self();
        
        // Protocol Version
        $clientHello->protocolVersion = substr($data, $offset, 2);
        $offset += 2;
        
        // Random
        $clientHello->random = substr($data, $offset, 32);
        $offset += 32;
        
        // Session ID
        if ($offset >= strlen($data)) {
            throw new InvalidParameterException("数据不完整：缺少 Session ID 长度");
        }
        $sessionIdLength = ord($data[$offset]);
        $offset++;
        if ($offset + $sessionIdLength > strlen($data)) {
            throw new InvalidParameterException("数据不完整：Session ID 数据不足");
        }
        $clientHello->sessionId = substr($data, $offset, $sessionIdLength);
        $offset += $sessionIdLength;
        
        // Cipher Suites
        if ($offset + 2 > strlen($data)) {
            throw new InvalidParameterException("数据不完整：缺少 Cipher Suites 长度");
        }
        $cipherSuitesData = substr($data, $offset, 2);
        if (strlen($cipherSuitesData) < 2) {
            throw new InvalidParameterException("数据不完整：Cipher Suites 长度数据不足");
        }
        $cipherSuitesLength = unpack('n', $cipherSuitesData)[1];
        $offset += 2;
        if ($offset + $cipherSuitesLength > strlen($data)) {
            throw new InvalidParameterException("数据不完整：Cipher Suites 数据不足");
        }
        $clientHello->cipherSuites = [];
        for ($i = 0; $i < $cipherSuitesLength; $i += 2) {
            if ($offset + $i + 2 <= strlen($data)) {
                $cipherSuiteData = substr($data, $offset + $i, 2);
                if (strlen($cipherSuiteData) === 2) {
                    $clientHello->cipherSuites[] = unpack('n', $cipherSuiteData)[1];
                }
            }
        }
        $offset += $cipherSuitesLength;
        
        // Compression Methods
        if ($offset >= strlen($data)) {
            throw new InvalidParameterException("数据不完整：缺少压缩方法长度");
        }
        $compressionLength = ord($data[$offset]);
        $offset++;
        $clientHello->compressionMethods = [];
        for ($i = 0; $i < $compressionLength; $i++) {
            $clientHello->compressionMethods[] = ord($data[$offset + $i]);
        }
        $offset += $compressionLength;
        
        // Extensions
        if ($offset < strlen($data)) {
            $extensionsLength = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;
            $clientHello->parseExtensions(substr($data, $offset, $extensionsLength));
        }
        
        return $clientHello;
    }

    /**
     * 构建扩展
     */
    private function buildExtensions(): void
    {
        // Server Name Indication (SNI)
        $this->extensions[0x0000] = $this->buildSNIExtension('localhost');
        
        // Supported Groups
        $this->extensions[0x000a] = $this->buildSupportedGroupsExtension();
        
        // Signature Algorithms
        $this->extensions[0x000d] = $this->buildSignatureAlgorithmsExtension();
        
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
            $data .= pack('n', $type); // Extension Type
            $data .= pack('n', strlen($extensionData)); // Extension Length
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
     * 构建SNI扩展
     */
    private function buildSNIExtension(string $hostname): string
    {
        $data = pack('n', strlen($hostname) + 3); // Server Name List Length
        $data .= chr(0x00); // Name Type: host_name
        $data .= pack('n', strlen($hostname)); // Host Name Length
        $data .= $hostname;
        
        return $data;
    }

    /**
     * 构建支持的椭圆曲线扩展
     */
    private function buildSupportedGroupsExtension(): string
    {
        $groups = [
            0x0017, // secp256r1
            0x0018, // secp384r1
            0x0019, // secp521r1
            0x001d, // x25519
            0x001e, // x448
        ];
        
        $data = pack('n', count($groups) * 2); // Named Group List Length
        foreach ($groups as $group) {
            $data .= pack('n', $group);
        }
        
        return $data;
    }

    /**
     * 构建签名算法扩展
     */
    private function buildSignatureAlgorithmsExtension(): string
    {
        $algorithms = [
            0x0403, // ecdsa_secp256r1_sha256
            0x0503, // ecdsa_secp384r1_sha384
            0x0603, // ecdsa_secp521r1_sha512
            0x0804, // rsa_pss_rsae_sha256
            0x0805, // rsa_pss_rsae_sha384
            0x0806, // rsa_pss_rsae_sha512
        ];
        
        $data = pack('n', count($algorithms) * 2); // Signature Hash Algorithms Length
        foreach ($algorithms as $algorithm) {
            $data .= pack('n', $algorithm);
        }
        
        return $data;
    }

    /**
     * 构建支持的版本扩展
     */
    private function buildSupportedVersionsExtension(): string
    {
        $versions = [
            0x0304, // TLS 1.3
        ];
        
        $data = chr(count($versions) * 2); // Supported Versions Length
        foreach ($versions as $version) {
            $data .= pack('n', $version);
        }
        
        return $data;
    }

    /**
     * 构建密钥共享扩展
     */
    private function buildKeyShareExtension(): string
    {
        // 生成x25519密钥对
        $privateKey = random_bytes(32);
        $publicKey = $this->generateX25519PublicKey($privateKey);
        
        $data = pack('n', 2 + 2 + strlen($publicKey)); // Client Key Share Length
        $data .= pack('n', 0x001d); // Named Group: x25519
        $data .= pack('n', strlen($publicKey)); // Key Exchange Length
        $data .= $publicKey;
        
        return $data;
    }

    /**
     * 生成x25519公钥（简化实现）
     */
    private function generateX25519PublicKey(string $privateKey): string
    {
        // 这里应该使用sodium_crypto_scalarmult_base或类似函数
        // 简化实现，返回32字节随机数据
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
     * 获取随机数
     */
    public function getRandom(): string
    {
        return $this->random;
    }

    /**
     * 获取会话ID
     */
    public function getSessionId(): string
    {
        return $this->sessionId;
    }

    /**
     * 获取密码套件
     */
    public function getCipherSuites(): array
    {
        return $this->cipherSuites;
    }

    /**
     * 获取扩展
     */
    public function getExtensions(): array
    {
        return $this->extensions;
    }

    /**
     * 获取特定扩展
     */
    public function getExtension(int $type): ?string
    {
        return $this->extensions[$type] ?? null;
    }
    
    /**
     * 设置随机数
     */
    public function setRandom(string $random): void
    {
        $this->random = $random;
    }
    
    /**
     * 设置密码套件
     */
    public function setCipherSuites(array $cipherSuites): void
    {
        $this->cipherSuites = $cipherSuites;
    }
    
    /**
     * 设置扩展
     */
    public function setExtensions(array $extensions): void
    {
        $this->extensions = $extensions;
    }
} 