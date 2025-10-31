<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS;

use Tourze\QUIC\TLS\Exception\TlsProtocolException;

/**
 * TLS 1.3密钥调度器
 *
 * 根据RFC 8446实现TLS 1.3密钥派生和管理
 */
class KeyScheduler
{
    // TLS 1.3标签
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
    /** @var array{client: ?string, server: ?string} */
    private array $handshakeKeys = [
        'client' => null,
        'server' => null,
    ];

    /** @var array{client: ?string, server: ?string} */
    private array $applicationKeys = [
        'client' => null,
        'server' => null,
    ];

    private string $cipherSuite = 'TLS_AES_128_GCM_SHA256'; // 默认使用 AES-128

    /** @var int<1, max> */
    private int $ivLength = 12; // GCM IV长度

    public function __construct(string $cipherSuite = 'TLS_AES_128_GCM_SHA256')
    {
        $this->cipherSuite = $cipherSuite;
        $this->initializeSecrets();
    }

    /**
     * 获取密码套件对应的哈希算法
     *
     * @return non-falsy-string
     */
    private function getHashAlgorithm(): string
    {
        return match ($this->cipherSuite) {
            'TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256', 'sha256' => 'sha256',
            'TLS_AES_256_GCM_SHA384', 'sha384' => 'sha384',
            'sha512' => 'sha512',
            default => 'sha256', // 默认使用 SHA256
        };
    }

    /**
     * 初始化Early Secret
     */
    private function initializeSecrets(): void
    {
        // Early Secret = HKDF-Extract(0, 0)
        $zeroKey = str_repeat("\x00", $this->getHashLength());
        $hashAlgo = $this->getHashAlgorithm();
        $this->earlySecret = hash_hkdf($hashAlgo, $zeroKey, $this->getHashLength());
    }

    /**
     * 派生握手密钥
     */
    public function deriveHandshakeSecrets(string $sharedSecret, string $transcriptHash): void
    {
        // Derive-Secret for handshake
        $derivedSecret = $this->deriveSecret($this->earlySecret, self::LABEL_TLS13_DERIVED, '');

        // Handshake Secret = HKDF-Extract(Derived-Secret, (EC)DHE)
        $hashAlgo = $this->getHashAlgorithm();
        $this->handshakeSecret = hash_hkdf($hashAlgo, $sharedSecret, $this->getHashLength(), '', $derivedSecret);

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
     *
     * @return array{client_application_traffic_secret: ?string, server_application_traffic_secret: ?string, client_application_traffic_secret_0: ?string, server_application_traffic_secret_0: ?string, exporter_master_secret: string}
     */
    public function deriveApplicationSecrets(string $transcriptHash): array
    {
        // Derive-Secret for master
        $derivedSecret = $this->deriveSecret($this->handshakeSecret, self::LABEL_TLS13_DERIVED, '');

        // Master Secret = HKDF-Extract(Derived-Secret, 0)
        $zeroKey = str_repeat("\x00", $this->getHashLength());
        $hashAlgo = $this->getHashAlgorithm();
        $hashLength = $this->getHashLength();
        $this->masterSecret = hash_hkdf($hashAlgo, $zeroKey, $hashLength, '', $derivedSecret);

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

        return [
            'client_application_traffic_secret' => $this->applicationKeys['client'],
            'server_application_traffic_secret' => $this->applicationKeys['server'],
            'client_application_traffic_secret_0' => $this->applicationKeys['client'], // 兼容性别名
            'server_application_traffic_secret_0' => $this->applicationKeys['server'], // 兼容性别名
            'exporter_master_secret' => $this->deriveSecret($this->masterSecret, self::LABEL_TLS13_EXPORTER_MASTER, $transcriptHash),
        ];
    }

    /**
     * 计算Finished消息的MAC
     */
    public function computeFinishedMAC(string $transcriptHash, bool $isServer): string
    {
        $baseKey = $isServer ? $this->handshakeKeys['server'] : $this->handshakeKeys['client'];

        if (null === $baseKey) {
            throw new TlsProtocolException('握手密钥未初始化');
        }

        // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
        $finishedKey = $this->hkdfExpandLabel($baseKey, self::LABEL_TLS13_FINISHED, '', $this->getHashLength());

        // verify_data = HMAC(finished_key, transcript_hash)
        return hash_hmac($this->getHashAlgorithm(), $transcriptHash, $finishedKey, true);
    }

    /**
     * 更新流量密钥（用于密钥更新）
     */
    public function updateKeys(): void
    {
        if (null !== $this->applicationKeys['client']) {
            $this->applicationKeys['client'] = $this->hkdfExpandLabel(
                $this->applicationKeys['client'],
                'tls13 traffic upd',
                '',
                $this->getHashLength()
            );
        }

        if (null !== $this->applicationKeys['server']) {
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
     *
     * @param int<1, max> $length
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
        $hashAlgo = $this->getHashAlgorithm();

        return $this->hkdfExpandLabel($secret, $label, hash($hashAlgo, $context, true), $this->getHashLength());
    }

    /**
     * 获取哈希函数输出长度
     *
     * @return int<1, max>
     */
    private function getHashLength(): int
    {
        $hashAlgo = $this->getHashAlgorithm();

        return match ($hashAlgo) {
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
            default => 32,
        };
    }

    /**
     * 派生QUIC密钥和IV
     *
     * @return array{key: string, iv: string, header_protection: string}
     */
    public function deriveQuicKeys(string $trafficSecret): array
    {
        $keyLength = $this->getCipherKeyLength();
        $key = $this->hkdfExpandLabel($trafficSecret, 'quic key', '', $keyLength);
        $iv = $this->hkdfExpandLabel($trafficSecret, 'quic iv', '', $this->ivLength);
        $headerProtectionKey = $this->hkdfExpandLabel($trafficSecret, 'quic hp', '', $keyLength);

        return [
            'key' => $key,
            'iv' => $iv,
            'header_protection' => $headerProtectionKey,
        ];
    }

    /**
     * 获取密码套件对应的密钥长度
     *
     * @return int<1, max>
     */
    private function getCipherKeyLength(): int
    {
        return match ($this->cipherSuite) {
            'TLS_AES_128_GCM_SHA256' => 16,
            'TLS_AES_256_GCM_SHA384' => 32,
            'TLS_CHACHA20_POLY1305_SHA256' => 32,
            default => 16, // 默认使用 AES-128
        };
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
        return '' !== $this->handshakeSecret || '' !== $this->masterSecret
               || null !== $this->handshakeKeys['client'] || null !== $this->handshakeKeys['server']
               || null !== $this->applicationKeys['client'] || null !== $this->applicationKeys['server'];
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
        // 验证密码套件是否有效
        $validCipherSuites = [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'sha256',
            'sha384',
            'sha512',
        ];

        if (!in_array($cipherSuite, $validCipherSuites, true)) {
            throw new \ValueError("Invalid cipher suite: {$cipherSuite}");
        }

        $this->cipherSuite = $cipherSuite;
        $this->reset(); // 重新初始化
    }

    /**
     * 设置 Early Secret
     */
    public function setEarlySecret(string $psk): void
    {
        $zeroSalt = str_repeat("\x00", $this->getHashLength());
        $hashAlgo = $this->getHashAlgorithm();
        $hashLength = $this->getHashLength();
        if ('' === $psk) {
            $zeroKey = str_repeat("\x00", $hashLength);
            $this->earlySecret = hash_hkdf($hashAlgo, $zeroKey, $hashLength, '', $zeroSalt);
        } else {
            $this->earlySecret = hash_hkdf($hashAlgo, $psk, $hashLength, '', $zeroSalt);
        }
    }

    /**
     * 获取 Early Secret
     */
    public function getEarlySecret(): string
    {
        return $this->earlySecret;
    }

    /**
     * 派生 Master Secret
     */
    public function deriveMasterSecret(): string
    {
        $derivedSecret = $this->deriveSecret($this->handshakeSecret, self::LABEL_TLS13_DERIVED, '');
        $zeroKey = str_repeat("\x00", $this->getHashLength());
        $hashAlgo = $this->getHashAlgorithm();
        $this->masterSecret = hash_hkdf($hashAlgo, $zeroKey, $this->getHashLength(), '', $derivedSecret);

        return $this->masterSecret;
    }

    /**
     * 获取应用密钥
     *
     * @return array{client: ?string, server: ?string}
     */
    public function getApplicationSecrets(): array
    {
        return $this->applicationKeys;
    }

    /**
     * 导出密钥材料
     *
     * @param int<1, max> $length
     */
    public function exportKeyingMaterial(string $masterSecret, string $label, string $context, int $length): string
    {
        return $this->hkdfExpandLabel($masterSecret, 'exp ' . $label, $context, $length);
    }

    /**
     * 派生恢复主密钥
     */
    public function deriveResumptionMasterSecret(string $transcriptHash): string
    {
        return $this->deriveSecret($this->masterSecret, self::LABEL_TLS13_RESUMPTION, $transcriptHash);
    }

    /**
     * 派生早期数据密钥
     *
     * @return array{client_early_traffic_secret: string, early_exporter_master_secret: string}
     */
    public function deriveEarlyDataKeys(): array
    {
        $clientEarlySecret = $this->deriveSecret($this->earlySecret, 'tls13 c e traffic', '');
        $earlyExporterSecret = $this->deriveSecret($this->earlySecret, 'tls13 e exp master', '');

        return [
            'client_early_traffic_secret' => $clientEarlySecret,
            'early_exporter_master_secret' => $earlyExporterSecret,
        ];
    }

    /**
     * 让 hkdfExpandLabel 方法公开
     *
     * @param int<1, max> $length
     */
    public function hkdfExpandLabel(string $secret, string $label, string $context, int $length): string
    {
        // 构建 HkdfLabel 结构
        // struct {
        //     uint16 length = Length;
        //     opaque label<7..255> = "tls13 " + Label;
        //     opaque context<0..255> = Context;
        // } HkdfLabel;

        $fullLabel = 'tls13 ' . $label;

        $hkdfLabel = pack('n', $length); // length (2 bytes)
        $hkdfLabel .= chr(strlen($fullLabel)) . $fullLabel; // label with length prefix
        $hkdfLabel .= chr(strlen($context)) . $context; // context with length prefix

        $hashAlgo = $this->getHashAlgorithm();

        return hash_hkdf($hashAlgo, $secret, $length, $hkdfLabel);
    }

    /**
     * 返回握手密钥派生结果 (重载方法)
     *
     * @return array{handshake_secret: string, client_handshake_traffic_secret: ?string, server_handshake_traffic_secret: ?string}
     */
    public function deriveHandshakeSecretsWithResult(string $sharedSecret, string $transcriptHash = ''): array
    {
        $this->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        return [
            'handshake_secret' => $this->handshakeSecret,
            'client_handshake_traffic_secret' => $this->handshakeKeys['client'],
            'server_handshake_traffic_secret' => $this->handshakeKeys['server'],
        ];
    }
}
