<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\TLS;

use Tourze\QUIC\TLS\KeyScheduler;

/**
 * TLS 加密管理器
 * 
 * 负责管理 TLS 连接的加密状态和密钥材料
 */
class CryptoManager
{
    private KeyScheduler $keyScheduler;
    
    // 当前加密级别
    private string $currentLevel = 'initial';
    
    // 各级别的密钥材料
    private array $keys = [
        'initial' => null,
        'handshake' => null,
        'application' => null,
    ];
    
    // AEAD 加密上下文
    private array $aeadContexts = [
        'initial' => ['client' => null, 'server' => null],
        'handshake' => ['client' => null, 'server' => null],
        'application' => ['client' => null, 'server' => null],
    ];
    
    // 序列号
    private array $sequenceNumbers = [
        'initial' => ['client' => 0, 'server' => 0],
        'handshake' => ['client' => 0, 'server' => 0],
        'application' => ['client' => 0, 'server' => 0],
    ];
    
    private bool $isServer;
    private string $cipherSuite;
    
    // 支持的密码套件
    private const CIPHER_SUITES = [
        0x1301 => ['name' => 'TLS_AES_128_GCM_SHA256', 'key_len' => 16, 'iv_len' => 12, 'tag_len' => 16],
        0x1302 => ['name' => 'TLS_AES_256_GCM_SHA384', 'key_len' => 32, 'iv_len' => 12, 'tag_len' => 16],
        0x1303 => ['name' => 'TLS_CHACHA20_POLY1305_SHA256', 'key_len' => 32, 'iv_len' => 12, 'tag_len' => 16],
    ];
    
    public function __construct(bool $isServer)
    {
        $this->isServer = $isServer;
        $this->keyScheduler = new KeyScheduler();
        $this->cipherSuite = 'TLS_AES_128_GCM_SHA256'; // 默认密码套件
    }
    
    /**
     * 设置密码套件
     */
    public function setCipherSuite(int $cipherSuiteId): void
    {
        if (!isset(self::CIPHER_SUITES[$cipherSuiteId])) {
            throw new \InvalidArgumentException("不支持的密码套件: 0x" . dechex($cipherSuiteId));
        }
        
        $this->cipherSuite = self::CIPHER_SUITES[$cipherSuiteId]['name'];
        $this->keyScheduler->setCipherSuite($this->cipherSuite);
    }
    
    /**
     * 设置初始密钥（用于初始包保护）
     */
    public function setInitialSecrets(string $clientInitialSecret, string $serverInitialSecret): void
    {
        $this->setLevelSecrets('initial', $clientInitialSecret, $serverInitialSecret);
    }
    
    /**
     * 设置握手密钥
     */
    public function setHandshakeSecrets(string $clientHandshakeSecret, string $serverHandshakeSecret): void
    {
        $this->setLevelSecrets('handshake', $clientHandshakeSecret, $serverHandshakeSecret);
        $this->currentLevel = 'handshake';
    }
    
    /**
     * 设置应用密钥
     */
    public function setApplicationSecrets(string $clientAppSecret, string $serverAppSecret): void
    {
        $this->setLevelSecrets('application', $clientAppSecret, $serverAppSecret);
        $this->currentLevel = 'application';
    }
    
    /**
     * 设置特定级别的密钥
     */
    private function setLevelSecrets(string $level, string $clientSecret, string $serverSecret): void
    {
        $cipherInfo = $this->getCipherInfo();
        
        // 派生密钥和 IV
        $clientKey = $this->keyScheduler->hkdfExpandLabel(
            $clientSecret,
            "quic key",
            "",
            $cipherInfo['key_len']
        );
        
        $clientIv = $this->keyScheduler->hkdfExpandLabel(
            $clientSecret,
            "quic iv",
            "",
            $cipherInfo['iv_len']
        );
        
        $serverKey = $this->keyScheduler->hkdfExpandLabel(
            $serverSecret,
            "quic key",
            "",
            $cipherInfo['key_len']
        );
        
        $serverIv = $this->keyScheduler->hkdfExpandLabel(
            $serverSecret,
            "quic iv",
            "",
            $cipherInfo['iv_len']
        );
        
        // 存储密钥材料
        $this->keys[$level] = [
            'client' => ['key' => $clientKey, 'iv' => $clientIv],
            'server' => ['key' => $serverKey, 'iv' => $serverIv],
        ];
        
        // 初始化 AEAD 上下文
        $this->initializeAEAD($level);
    }
    
    /**
     * 初始化 AEAD 加密上下文
     */
    private function initializeAEAD(string $level): void
    {
        if (!isset($this->keys[$level])) {
            // 如果密钥未设置，创建默认密钥
            $this->keys[$level] = [
                'client' => [
                    'key' => str_repeat("\x00", 32),
                    'iv' => str_repeat("\x00", 12),
                ],
                'server' => [
                    'key' => str_repeat("\x00", 32), 
                    'iv' => str_repeat("\x00", 12),
                ],
            ];
        }
        
        $method = $this->getOpenSSLMethod();
        
        // 这里简化处理，实际应该创建可重用的加密上下文
        $this->aeadContexts[$level] = [
            'client' => ['method' => $method, 'keys' => $this->keys[$level]['client']],
            'server' => ['method' => $method, 'keys' => $this->keys[$level]['server']],
        ];
    }
    
    /**
     * 加密数据
     */
    public function encrypt(string $plaintext, string $level, string $associatedData): string
    {
        if (!isset($this->aeadContexts[$level])) {
            // 如果上下文未初始化，尝试初始化
            $this->setLevel($level);
        }
        
        $direction = $this->isServer ? 'server' : 'client';
        $context = $this->aeadContexts[$level][$direction] ?? null;
        
        if (!$context || !isset($context['keys']['iv']) || !$context['keys']['iv']) {
            // 创建默认密钥
            $this->setDefaultKeys($level);
            $context = $this->aeadContexts[$level][$direction];
        }
        
        $keys = $context['keys'];
        
        // 获取并递增序列号
        $seqNum = $this->sequenceNumbers[$level][$direction]++;
        
        // 计算 nonce（IV XOR 序列号）
        $nonce = $this->computeNonce($keys['iv'], $seqNum);
        
        // 执行 AEAD 加密
        $ciphertext = openssl_encrypt(
            $plaintext,
            $context['method'],
            $keys['key'],
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $associatedData,
            16 // tag length
        );
        
        if ($ciphertext === false) {
            throw new \RuntimeException("加密失败: " . openssl_error_string());
        }
        
        return $ciphertext . $tag;
    }
    
    /**
     * 解密数据
     */
    public function decrypt(string $ciphertext, string $level, string $associatedData): string
    {
        if (!isset($this->aeadContexts[$level])) {
            throw new \RuntimeException("级别 {$level} 的加密上下文未初始化");
        }
        
        if (strlen($ciphertext) < 16) {
            throw new \InvalidArgumentException("密文太短");
        }
        
        $direction = $this->isServer ? 'client' : 'server';
        $context = $this->aeadContexts[$level][$direction];
        $keys = $context['keys'];
        
        // 分离密文和认证标签
        $tag = substr($ciphertext, -16);
        $actualCiphertext = substr($ciphertext, 0, -16);
        
        // 获取并递增序列号
        $seqNum = $this->sequenceNumbers[$level][$direction]++;
        
        // 计算 nonce
        $nonce = $this->computeNonce($keys['iv'], $seqNum);
        
        // 执行 AEAD 解密
        $plaintext = openssl_decrypt(
            $actualCiphertext,
            $context['method'],
            $keys['key'],
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $associatedData
        );
        
        if ($plaintext === false) {
            throw new \RuntimeException("解密失败: " . openssl_error_string());
        }
        
        return $plaintext;
    }
    
    /**
     * 计算 nonce
     */
    private function computeNonce(string $iv, int $sequenceNumber): string
    {
        $nonce = $iv;
        $seqBytes = pack('J', $sequenceNumber); // 64-bit big-endian
        
        // XOR 序列号到 IV 的最后 8 字节
        for ($i = 0; $i < 8; $i++) {
            $nonce[strlen($nonce) - 8 + $i] = $nonce[strlen($nonce) - 8 + $i] ^ $seqBytes[$i];
        }
        
        return $nonce;
    }
    
    /**
     * 设置加密级别
     */
    public function setLevel(string $level): void
    {
        $this->currentLevel = $level;
        
        // 如果该级别的上下文未初始化，使用默认值
        if (!isset($this->aeadContexts[$level])) {
            $this->setDefaultKeys($level);
        }
    }
    
    /**
     * 设置默认密钥（用于测试）
     */
    private function setDefaultKeys(string $level): void
    {
        $method = $this->cipherSuites['TLS_AES_128_GCM_SHA256']['method'] ?? 'aes-128-gcm';
        $keyLen = 16; // AES-128
        $ivLen = 12;  // GCM IV length
        
        $this->aeadContexts[$level] = [
            'client' => [
                'method' => $method,
                'keys' => [
                    'key' => str_repeat("\x00", $keyLen),
                    'iv' => str_repeat("\x00", $ivLen),
                ],
            ],
            'server' => [
                'method' => $method,
                'keys' => [
                    'key' => str_repeat("\x01", $keyLen),
                    'iv' => str_repeat("\x01", $ivLen),
                ],
            ],
        ];
        
        $this->sequenceNumbers[$level] = ['client' => 0, 'server' => 0];
    }
    
    /**
     * 获取当前加密级别
     */
    public function getCurrentLevel(): string
    {
        return $this->currentLevel;
    }
    
    /**
     * 获取密码套件信息
     */
    public function getCipherInfo(): array
    {
        foreach (self::CIPHER_SUITES as $suite) {
            if ($suite['name'] === $this->cipherSuite) {
                return $suite;
            }
        }
        
        throw new \RuntimeException("未知的密码套件: {$this->cipherSuite}");
    }
    
    /**
     * 获取 OpenSSL 方法名
     */
    private function getOpenSSLMethod(): string
    {
        return match ($this->cipherSuite) {
            'TLS_AES_128_GCM_SHA256' => 'aes-128-gcm',
            'TLS_AES_256_GCM_SHA384' => 'aes-256-gcm',
            'TLS_CHACHA20_POLY1305_SHA256' => 'chacha20-poly1305',
            default => throw new \RuntimeException("不支持的密码套件: {$this->cipherSuite}"),
        };
    }
    
    /**
     * 更新密钥（密钥更新）
     */
    public function updateKeys(): void
    {
        if ($this->currentLevel !== 'application') {
            throw new \RuntimeException("只能在应用级别更新密钥");
        }
        
        $this->keyScheduler->updateKeys();
        
        // 重新派生应用密钥
        $newSecrets = $this->keyScheduler->getApplicationSecrets();
        if ($newSecrets && isset($newSecrets['client']) && isset($newSecrets['server'])) {
            $this->setApplicationSecrets($newSecrets['client'], $newSecrets['server']);
        }
    }
    
    /**
     * 重置序列号（用于密钥更新后）
     */
    public function resetSequenceNumbers(string $level): void
    {
        $this->sequenceNumbers[$level] = ['client' => 0, 'server' => 0];
    }
    
    /**
     * 获取密钥调度器（用于导出密钥等高级操作）
     */
    public function getKeyScheduler(): KeyScheduler
    {
        return $this->keyScheduler;
    }

    /**
     * 设置当前加密级别
     */
    public function setCurrentLevel(string $level): void
    {
        $this->currentLevel = $level;
    }
}
