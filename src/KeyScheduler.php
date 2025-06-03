<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS;

/**
 * TLS 1.3密钥调度器
 * 
 * 根据RFC 8446实现TLS 1.3密钥派生和管理
 */
class KeyScheduler
{
    // TLS 1.3标签
    private const LABEL_TLS13_KEY = 'tls13 key';
    private const LABEL_TLS13_IV = 'tls13 iv';
    private const LABEL_TLS13_FINISHED = 'tls13 finished';
    private const LABEL_TLS13_RESUMPTION = 'tls13 resumption master secret';
    private const LABEL_TLS13_DERIVED = 'tls13 derived';
    private const LABEL_TLS13_CLIENT_HANDSHAKE_TRAFFIC = 'tls13 c hs traffic';
    private const LABEL_TLS13_SERVER_HANDSHAKE_TRAFFIC = 'tls13 s hs traffic';
    private const LABEL_TLS13_CLIENT_APPLICATION_TRAFFIC = 'tls13 c ap traffic';
    private const LABEL_TLS13_SERVER_APPLICATION_TRAFFIC = 'tls13 s ap traffic';
    private const LABEL_TLS13_EXPORTER_MASTER = 'tls13 exp master';

    // 密钥状态
    private string $earlySecret = '';
    private string $handshakeSecret = '';
    private string $masterSecret = '';
    
    // 流量密钥
    private array $handshakeKeys = [
        'client' => null,
        'server' => null,
    ];
    
    private array $applicationKeys = [
        'client' => null,
        'server' => null,
    ];

    private string $cipherSuite = 'sha256'; // 默认使用SHA-256
    private int $keyLength = 32; // AES-256密钥长度
    private int $ivLength = 12; // GCM IV长度

    public function __construct(string $cipherSuite = 'sha256')
    {
        $this->cipherSuite = $cipherSuite;
        $this->initializeSecrets();
    }

    /**
     * 初始化Early Secret
     */
    private function initializeSecrets(): void
    {
        // Early Secret = HKDF-Extract(0, 0)
        $this->earlySecret = hash_hkdf($this->cipherSuite, '', 0, '', '', true);
    }

    /**
     * 派生握手密钥
     */
    public function deriveHandshakeSecrets(string $sharedSecret, string $transcriptHash): void
    {
        // Derive-Secret for handshake
        $derivedSecret = $this->deriveSecret($this->earlySecret, self::LABEL_TLS13_DERIVED, '');
        
        // Handshake Secret = HKDF-Extract(Derived-Secret, (EC)DHE)
        $this->handshakeSecret = hash_hkdf($this->cipherSuite, $sharedSecret, 0, $derivedSecret, '', true);
        
        // 派生客户端和服务端握手流量密钥
        $this->handshakeKeys['client'] = $this->deriveSecret(
            $this->handshakeSecret,
            self::LABEL_TLS13_CLIENT_HANDSHAKE_TRAFFIC,
            $transcriptHash
        );
        
        $this->handshakeKeys['server'] = $this->deriveSecret(
            $this->handshakeSecret,
            self::LABEL_TLS13_SERVER_HANDSHAKE_TRAFFIC,
            $transcriptHash
        );
    }

    /**
     * 派生应用密钥
     */
    public function deriveApplicationSecrets(string $transcriptHash): void
    {
        // Derive-Secret for master
        $derivedSecret = $this->deriveSecret($this->handshakeSecret, self::LABEL_TLS13_DERIVED, '');
        
        // Master Secret = HKDF-Extract(Derived-Secret, 0)
        $this->masterSecret = hash_hkdf($this->cipherSuite, '', 0, $derivedSecret, '', true);
        
        // 派生客户端和服务端应用流量密钥
        $this->applicationKeys['client'] = $this->deriveSecret(
            $this->masterSecret,
            self::LABEL_TLS13_CLIENT_APPLICATION_TRAFFIC,
            $transcriptHash
        );
        
        $this->applicationKeys['server'] = $this->deriveSecret(
            $this->masterSecret,
            self::LABEL_TLS13_SERVER_APPLICATION_TRAFFIC,
            $transcriptHash
        );
    }

    /**
     * 计算Finished消息的MAC
     */
    public function computeFinishedMAC(string $transcriptHash, bool $isServer): string
    {
        $baseKey = $isServer ? $this->handshakeKeys['server'] : $this->handshakeKeys['client'];
        
        if ($baseKey === null) {
            throw new \RuntimeException('握手密钥未初始化');
        }
        
        // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
        $finishedKey = $this->hkdfExpandLabel($baseKey, self::LABEL_TLS13_FINISHED, '', $this->getHashLength());
        
        // verify_data = HMAC(finished_key, transcript_hash)
        return hash_hmac($this->cipherSuite, $transcriptHash, $finishedKey, true);
    }

    /**
     * 更新流量密钥（用于密钥更新）
     */
    public function updateKeys(): void
    {
        if ($this->applicationKeys['client'] !== null) {
            $this->applicationKeys['client'] = $this->hkdfExpandLabel(
                $this->applicationKeys['client'],
                'tls13 traffic upd',
                '',
                $this->getHashLength()
            );
        }
        
        if ($this->applicationKeys['server'] !== null) {
            $this->applicationKeys['server'] = $this->hkdfExpandLabel(
                $this->applicationKeys['server'],
                'tls13 traffic upd',
                '',
                $this->getHashLength()
            );
        }
    }

    /**
     * 获取握手密钥
     */
    public function getHandshakeKey(bool $isServer): ?string
    {
        return $isServer ? $this->handshakeKeys['server'] : $this->handshakeKeys['client'];
    }

    /**
     * 获取应用密钥
     */
    public function getApplicationKey(bool $isServer): ?string
    {
        return $isServer ? $this->applicationKeys['server'] : $this->applicationKeys['client'];
    }

    /**
     * 导出器主密钥（用于密钥导出）
     */
    public function getExporterMasterSecret(string $transcriptHash): string
    {
        return $this->deriveSecret($this->masterSecret, self::LABEL_TLS13_EXPORTER_MASTER, $transcriptHash);
    }

    /**
     * 导出密钥（用于QUIC密钥派生）
     */
    public function exportKey(string $label, string $context, int $length): string
    {
        $exporterSecret = $this->getExporterMasterSecret('');
        return $this->hkdfExpandLabel($exporterSecret, $label, $context, $length);
    }

    /**
     * Derive-Secret函数
     */
    private function deriveSecret(string $secret, string $label, string $context): string
    {
        return $this->hkdfExpandLabel($secret, $label, hash($this->cipherSuite, $context, true), $this->getHashLength());
    }

    /**
     * HKDF-Expand-Label函数
     */
    private function hkdfExpandLabel(string $secret, string $label, string $context, int $length): string
    {
        // struct {
        //     uint16 length = Length;
        //     opaque label<7..255> = "tls13 " + Label;
        //     opaque context<0..255> = Context;
        // } HkdfLabel;
        
        $hkdfLabel = pack('n', $length); // length (2 bytes)
        $hkdfLabel .= chr(strlen($label)) . $label; // label with length prefix
        $hkdfLabel .= chr(strlen($context)) . $context; // context with length prefix
        
        return hash_hkdf($this->cipherSuite, $secret, $length, $hkdfLabel, '', true);
    }

    /**
     * 获取哈希函数输出长度
     */
    private function getHashLength(): int
    {
        return match ($this->cipherSuite) {
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
            default => 32,
        };
    }

    /**
     * 派生QUIC密钥和IV
     */
    public function deriveQuicKeys(string $trafficSecret): array
    {
        $key = $this->hkdfExpandLabel($trafficSecret, 'quic key', '', $this->keyLength);
        $iv = $this->hkdfExpandLabel($trafficSecret, 'quic iv', '', $this->ivLength);
        $headerProtectionKey = $this->hkdfExpandLabel($trafficSecret, 'quic hp', '', $this->keyLength);
        
        return [
            'key' => $key,
            'iv' => $iv,
            'header_protection' => $headerProtectionKey,
        ];
    }

    /**
     * 生成恢复主密钥（用于0-RTT）
     */
    public function getResumptionMasterSecret(string $transcriptHash): string
    {
        return $this->deriveSecret($this->masterSecret, self::LABEL_TLS13_RESUMPTION, $transcriptHash);
    }

    /**
     * 验证密钥调度器状态
     */
    public function isReady(): bool
    {
        return !empty($this->earlySecret);
    }

    /**
     * 重置密钥调度器
     */
    public function reset(): void
    {
        $this->earlySecret = '';
        $this->handshakeSecret = '';
        $this->masterSecret = '';
        $this->handshakeKeys = ['client' => null, 'server' => null];
        $this->applicationKeys = ['client' => null, 'server' => null];
        $this->initializeSecrets();
    }

    /**
     * 获取当前使用的密码套件
     */
    public function getCipherSuite(): string
    {
        return $this->cipherSuite;
    }

    /**
     * 设置密码套件
     */
    public function setCipherSuite(string $cipherSuite): void
    {
        $this->cipherSuite = $cipherSuite;
        $this->reset(); // 重新初始化
    }
} 