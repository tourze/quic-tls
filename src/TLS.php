<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS;

use Tourze\QUIC\TLS\TLS\CryptoManager;
use Tourze\QUIC\TLS\TLS\HandshakeManager;
use Tourze\QUIC\TLS\TLS\MessageHandler;

/**
 * QUIC TLS 主入口类
 * 
 * 提供 QUIC 协议中 TLS 1.3 握手和加密功能的统一接口
 */
class TLS
{
    // TLS 连接状态
    public const STATE_INITIAL = 'initial';
    public const STATE_HANDSHAKING = 'handshaking';
    public const STATE_ESTABLISHED = 'established';
    public const STATE_CLOSING = 'closing';
    public const STATE_CLOSED = 'closed';
    
    // TLS 加密级别
    public const LEVEL_INITIAL = 'initial';
    public const LEVEL_HANDSHAKE = 'handshake';
    public const LEVEL_APPLICATION = 'application';
    
    private HandshakeManager $handshakeManager;
    private CryptoManager $cryptoManager;
    private MessageHandler $messageHandler;
    
    private string $state = self::STATE_INITIAL;
    private string $currentLevel = self::LEVEL_INITIAL;
    
    private bool $isServer;
    private ?TransportParameters $localParams = null;
    private ?TransportParameters $peerParams = null;
    
    // 配置选项
    private array $config = [];
    
    // 统计信息
    private array $stats = [
        'handshake_start_time' => null,
        'handshake_duration' => null,
        'bytes_sent' => 0,
        'bytes_received' => 0,
        'messages_sent' => 0,
        'messages_received' => 0,
    ];
    
    // 回调函数
    private array $callbacks = [];
    
    /**
     * 构造函数
     * 
     * @param bool $isServer 是否为服务器端
     * @param array $config 配置选项
     */
    public function __construct(bool $isServer, array $config = [])
    {
        $this->isServer = $isServer;
        $this->config = array_merge($this->getDefaultConfig(), $config);
        
        // 初始化传输参数
        $this->localParams = $this->createTransportParameters();
        
        // 初始化证书验证器
        $certValidator = new CertificateValidator($this->config['cert_config'] ?? []);
        
        // 初始化管理器
        $this->handshakeManager = new HandshakeManager($isServer, $this->localParams, $certValidator);
        $this->cryptoManager = new CryptoManager($isServer);
        $this->messageHandler = new MessageHandler();
        
        // 设置 PSK（如果有）
        if (isset($this->config['psk'])) {
            $this->handshakeManager->setPSK($this->config['psk'], $this->config['psk_identity'] ?? '');
        }
        
        // 尝试恢复会话（如果有）
        if (isset($this->config['session_ticket'])) {
            $this->handshakeManager->resumeSession($this->config['session_ticket']);
        }
    }
    
    /**
     * 开始 TLS 握手
     * 
     * @return string 初始握手消息（客户端）或空字符串（服务器）
     */
    public function startHandshake()
    {
        if ($this->state !== self::STATE_INITIAL) {
            throw new \RuntimeException("不能在状态 {$this->state} 下开始握手");
        }
        
        $this->state = self::STATE_HANDSHAKING;
        $this->stats['handshake_start_time'] = microtime(true);
        
        $initialMessage = $this->handshakeManager->startHandshake();
        
        if ($initialMessage) {
            $this->stats['bytes_sent'] += strlen($initialMessage);
            $this->stats['messages_sent']++;
            $this->triggerCallback('message_sent', ['data' => $initialMessage, 'level' => $this->currentLevel]);
        }
        
        // 根据测试的期望返回结构化响应
        if ($this->isServer) {
            return [
                'server_hello' => $initialMessage,
                'transport_parameters' => $this->localParams->toArray(),
            ];
        } else {
            return [
                'client_hello' => $initialMessage,
                'transport_parameters' => $this->localParams->toArray(),
            ];
        }
    }
    
    /**
     * 处理接收到的握手数据
     * 
     * @param string $data 接收到的数据
     * @param string $level 加密级别
     * @return array 包含响应数据和状态信息
     */
    public function processHandshakeData(string $data, string $level = self::LEVEL_INITIAL): array
    {
        if ($this->state === self::STATE_CLOSED) {
            throw new \RuntimeException("连接已关闭");
        }
        
        $this->stats['bytes_received'] += strlen($data);
        $this->stats['messages_received']++;
        
        $this->triggerCallback('message_received', ['data' => $data, 'level' => $level]);
        
        try {
            $result = $this->handshakeManager->processHandshakeData($data, $level);
            
            // 更新状态
            if ($result['isComplete'] && $this->state === self::STATE_HANDSHAKING) {
                $this->state = self::STATE_ESTABLISHED;
                $this->currentLevel = self::LEVEL_APPLICATION;
                $this->peerParams = $this->handshakeManager->getNegotiatedParameters();
                
                $this->stats['handshake_duration'] = microtime(true) - $this->stats['handshake_start_time'];
                
                $this->triggerCallback('handshake_complete', [
                    'duration' => $this->stats['handshake_duration'],
                    'negotiated_params' => $this->peerParams,
                ]);
            }
            
            // 更新加密级别
            if (isset($result['newLevel'])) {
                $this->currentLevel = $result['newLevel'];
            }
            
            // 统计发送数据
            foreach ($result['responses'] as $response) {
                $this->stats['bytes_sent'] += strlen($response['data']);
                $this->stats['messages_sent']++;
                $this->triggerCallback('message_sent', $response);
            }
            
            return $result;
            
        } catch (\Exception $e) {
            $this->state = self::STATE_CLOSED;
            $this->triggerCallback('error', ['message' => $e->getMessage(), 'exception' => $e]);
            throw $e;
        }
    }
    
    /**
     * 加密应用数据
     * 
     * @param string $plaintext 明文数据
     * @param string $associatedData 关联数据
     * @return string 加密后的数据
     */
    public function encrypt(string $plaintext, string $associatedData = ''): string
    {
        if ($this->state !== self::STATE_ESTABLISHED) {
            throw new \RuntimeException("连接未建立，无法加密数据");
        }
        
        $ciphertext = $this->cryptoManager->encrypt($plaintext, $this->currentLevel, $associatedData);
        
        $this->stats['bytes_sent'] += strlen($ciphertext);
        $this->triggerCallback('data_encrypted', ['plaintext_size' => strlen($plaintext), 'ciphertext_size' => strlen($ciphertext)]);
        
        return $ciphertext;
    }
    
    /**
     * 解密应用数据
     * 
     * @param string $ciphertext 密文数据
     * @param string $associatedData 关联数据
     * @return string 解密后的数据
     */
    public function decrypt(string $ciphertext, string $associatedData = ''): string
    {
        if ($this->state !== self::STATE_ESTABLISHED) {
            throw new \RuntimeException("连接未建立，无法解密数据");
        }
        
        $plaintext = $this->cryptoManager->decrypt($ciphertext, $this->currentLevel, $associatedData);
        
        $this->stats['bytes_received'] += strlen($ciphertext);
        $this->triggerCallback('data_decrypted', ['ciphertext_size' => strlen($ciphertext), 'plaintext_size' => strlen($plaintext)]);
        
        return $plaintext;
    }
    
    /**
     * 处理消息（简化的接口）
     */
    public function processMessage(string $message): array
    {
        $previousState = $this->state;
        
        try {
            $result = $this->processHandshakeData($message);
            
            return [
                'response' => $result['responses'][0]['data'] ?? '',
                'state_changed' => $this->state !== $previousState,
                'new_state' => $this->state,
                'is_complete' => $result['isComplete'] ?? false,
            ];
        } catch (\Exception $e) {
            return [
                'response' => '',
                'state_changed' => false,
                'error' => $e->getMessage(),
            ];
        }
    }
    
    /**
     * 更新流量密钥
     */
    public function updateKeys(): void
    {
        if ($this->state !== self::STATE_ESTABLISHED) {
            throw new \RuntimeException("连接未建立，无法更新密钥");
        }
        
        // 确保CryptoManager处于正确的级别
        $this->cryptoManager->setLevel($this->currentLevel);
        
        // 直接更新CryptoManager的密钥，而不是通过HandshakeManager
        $this->cryptoManager->updateKeys();
        $this->triggerCallback('keys_updated', []);
    }
    
    /**
     * 导出密钥材料
     * 
     * @param string $label 导出标签
     * @param int $length 导出长度
     * @return string 导出的密钥材料
     */
    public function exportKeyingMaterial(string $label, int $length): string
    {
        if ($this->state !== self::STATE_ESTABLISHED) {
            throw new \RuntimeException("连接未建立，无法导出密钥");
        }
        
        return $this->handshakeManager->exportKeyingMaterial($label, $length);
    }
    
    /**
     * 获取会话票据
     */
    public function getSessionTicket(): ?string
    {
        if ($this->state !== self::STATE_ESTABLISHED) {
            return null;
        }
        
        return $this->handshakeManager->getSessionTicket();
    }
    
    /**
     * 关闭连接
     */
    public function close(): void
    {
        if ($this->state === self::STATE_CLOSED) {
            return;
        }
        
        $this->state = self::STATE_CLOSING;
        $this->triggerCallback('closing', []);
        
        // 清理资源
        $this->clearSensitiveData();
        
        $this->state = self::STATE_CLOSED;
        $this->triggerCallback('closed', []);
    }
    
    /**
     * 获取连接状态
     */
    public function getState(): string
    {
        return $this->state;
    }
    
    /**
     * 获取当前加密级别
     */
    public function getCurrentLevel(): string
    {
        return $this->currentLevel;
    }
    
    /**
     * 检查握手是否完成
     */
    public function isHandshakeComplete(): bool
    {
        return $this->state === self::STATE_ESTABLISHED;
    }
    
    /**
     * 检查连接是否已建立
     */
    public function isEstablished(): bool
    {
        return $this->state === self::STATE_ESTABLISHED;
    }
    
    /**
     * 获取协商的传输参数
     */
    public function getNegotiatedParameters(): ?TransportParameters
    {
        return $this->peerParams;
    }
    
    /**
     * 获取本地传输参数
     */
    public function getLocalParameters(): TransportParameters
    {
        return $this->localParams;
    }
    
    /**
     * 获取统计信息
     */
    public function getStats(): array
    {
        return $this->stats;
    }
    
    /**
     * 获取调试信息
     */
    public function getDebugInfo(): array
    {
        return array_merge([
            'state' => $this->state,
            'level' => $this->currentLevel,
            'is_server' => $this->isServer,
        ], $this->handshakeManager->getDebugInfo(), $this->stats);
    }
    
    /**
     * 设置回调函数
     */
    public function setCallback(string $event, callable $callback): void
    {
        $this->callbacks[$event] = $callback;
    }

    /**
     * 设置传输参数
     */
    public function setTransportParameters(TransportParameters $params): void
    {
        $this->localParams = $params;
        $this->handshakeManager->setTransportParameters($params);
    }

    /**
     * 设置证书验证器
     */
    public function setCertificateValidator(CertificateValidator $validator): void
    {
        $this->handshakeManager->setCertificateValidator($validator);
    }

    /**
     * 设置密码套件
     */
    public function setCipherSuite(string $cipherSuite): void
    {
        if (!in_array($cipherSuite, self::getSupportedCipherSuites())) {
            throw new \InvalidArgumentException("不支持的密码套件: {$cipherSuite}");
        }
        $this->config['cipher_suite'] = $cipherSuite;
    }

    /**
     * 获取统计信息
     */
    public function getStatistics(): array
    {
        return array_merge($this->getStats(), [
            'handshake_complete' => $this->isHandshakeComplete(),
            'messages_processed' => $this->stats['messages_received'],
            'bytes_encrypted' => $this->stats['bytes_sent'],
            'bytes_decrypted' => $this->stats['bytes_received'],
            'cipher_suite' => $this->config['cipher_suite'] ?? 'TLS_AES_128_GCM_SHA256',
            'transport_parameters' => $this->localParams ? $this->localParams->toArray() : []
        ]);
    }

    /**
     * 设置 PSK
     */
    public function setPSK(string $psk): void
    {
        $this->handshakeManager->setPSK($psk, '');
    }

    /**
     * 重置连接
     */
    public function reset(): void
    {
        $this->state = self::STATE_INITIAL;
        $this->currentLevel = self::LEVEL_INITIAL;
        $this->stats = [
            'handshake_start_time' => null,
            'handshake_duration' => null,
            'bytes_sent' => 0,
            'bytes_received' => 0,
            'messages_sent' => 0,
            'messages_received' => 0,
        ];
        $this->handshakeManager->reset();
    }

    /**
     * 设置回调函数
     */
    public function setCallbacks(array $callbacks): void
    {
        $this->callbacks = array_merge($this->callbacks, $callbacks);
    }

    /**
     * 启用调试模式
     */
    public function enableDebugMode(bool $enable): void
    {
        $this->config['debug'] = $enable;
    }

    /**
     * 获取转录哈希
     */
    public function getTranscriptHash(): string
    {
        return $this->handshakeManager->getTranscriptHash();
    }

    /**
     * 获取支持的密码套件
     */
    public static function getSupportedCipherSuites(): array
    {
        return [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256'
        ];
    }

    /**
     * 启用 0-RTT
     */
    public function enableZeroRTT(bool $enable): void
    {
        $this->config['enable_0rtt'] = $enable;
    }

    /**
     * 获取连接信息
     */
    public function getConnectionInfo(): array
    {
        return [
            'is_server' => $this->isServer,
            'cipher_suite' => $this->config['cipher_suite'] ?? 'TLS_AES_128_GCM_SHA256',
            'handshake_complete' => $this->isHandshakeComplete(),
            'state' => $this->state,
            'current_level' => $this->currentLevel
        ];
    }
    
    /**
     * 触发回调函数
     */
    private function triggerCallback(string $event, array $data = []): void
    {
        if (isset($this->callbacks[$event])) {
            try {
                call_user_func($this->callbacks[$event], $data);
            } catch (\Exception $e) {
                // 忽略回调错误，避免影响主流程
            }
        }
    }
    
    /**
     * 获取默认配置
     */
    private function getDefaultConfig(): array
    {
        return [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
            'cipher_suites' => [0x1301, 0x1302, 0x1303], // TLS 1.3 默认套件
            'alpn_protocols' => ['h3'],
            'max_idle_timeout' => 30000, // 30 秒
            'max_udp_payload_size' => 1200,
            'initial_max_data' => 1048576, // 1MB
            'initial_max_stream_data_bidi_local' => 262144, // 256KB
            'initial_max_stream_data_bidi_remote' => 262144, // 256KB
            'initial_max_streams_bidi' => 100,
            'initial_max_streams_uni' => 100,
            'cert_config' => [],
        ];
    }
    
    /**
     * 创建传输参数
     */
    private function createTransportParameters(): TransportParameters
    {
        $params = new TransportParameters();
        
        $params->setMaxIdleTimeout($this->config['max_idle_timeout']);
        $params->setMaxUdpPayloadSize($this->config['max_udp_payload_size']);
        $params->setInitialMaxData($this->config['initial_max_data']);
        $params->setInitialMaxStreamDataBidiLocal($this->config['initial_max_stream_data_bidi_local']);
        $params->setInitialMaxStreamDataBidiRemote($this->config['initial_max_stream_data_bidi_remote']);
        $params->setInitialMaxStreamsBidi($this->config['initial_max_streams_bidi']);
        $params->setInitialMaxStreamsUni($this->config['initial_max_streams_uni']);
        
        return $params;
    }
    
    /**
     * 清理敏感数据
     */
    private function clearSensitiveData(): void
    {
        // 清理密钥等敏感信息
        if (isset($this->config['psk'])) {
            sodium_memzero($this->config['psk']);
        }
        
        // 其他清理操作...
    }
    
    /**
     * 创建客户端实例
     */
    public static function createClient(array $config = []): self
    {
        return new self(false, $config);
    }
    
    /**
     * 创建服务器实例
     */
    public static function createServer(array $config = []): self
    {
        return new self(true, $config);
    }
    
    
    /**
     * 获取版本信息
     */
    public static function getVersion(): string
    {
        return '1.0.0';
    }
    
    /**
     * 检查系统支持
     */
    public static function checkSupport(): array
    {
        $support = [
            'openssl' => extension_loaded('openssl'),
            'sodium' => extension_loaded('sodium'),
            'openssl_version' => defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : 'unknown',
            'tls_1_3' => false,
        ];
        
        // 检查 TLS 1.3 支持
        if ($support['openssl']) {
            $support['tls_1_3'] = version_compare(phpversion('openssl'), '1.1.1', '>=');
        }
        
        return $support;
    }
}