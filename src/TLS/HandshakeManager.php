<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\TLS;

use Tourze\QUIC\TLS\CertificateValidator;
use Tourze\QUIC\TLS\HandshakeStateMachine;
use Tourze\QUIC\TLS\KeyScheduler;
use Tourze\QUIC\TLS\TransportParameters;

/**
 * TLS 握手管理器
 * 
 * 管理 TLS 握手的高级操作和状态协调
 */
class HandshakeManager
{
    private HandshakeStateMachine $stateMachine;
    private CryptoManager $cryptoManager;
    private MessageHandler $messageHandler;
    private KeyScheduler $keyScheduler;
    
    private bool $isServer;
    private ?TransportParameters $localParams = null;
    private ?TransportParameters $peerParams = null;
    private ?CertificateValidator $certValidator = null;
    
    // 握手消息缓冲区
    private array $pendingMessages = [];
    private string $transcriptBuffer = '';
    private array $receivedMessages = [];
    
    // 握手密钥
    private ?string $handshakeSecret = null;
    private ?string $masterSecret = null;
    
    // 会话恢复
    private ?string $psk = null;
    private ?string $pskIdentity = null;
    
    public function __construct(
        bool $isServer,
        ?TransportParameters $localParams = null,
        ?CertificateValidator $certValidator = null
    ) {
        $this->isServer = $isServer;
        $this->localParams = $localParams;
        $this->certValidator = $certValidator ?? new CertificateValidator();
        
        $this->stateMachine = new HandshakeStateMachine($isServer, $this->localParams ?? new TransportParameters(), $this->certValidator);
        $this->cryptoManager = new CryptoManager($isServer);
        $this->messageHandler = new MessageHandler();
        $this->keyScheduler = new KeyScheduler();
    }
    
    /**
     * 开始握手过程
     * 
     * @return string 初始握手消息（客户端返回 ClientHello）
     */
    public function startHandshake(): string
    {
        if (!$this->localParams) {
            throw new \RuntimeException('传输参数未设置');
        }
        
        if (!$this->isServer) {
            $handshakeMessage = $this->stateMachine->startClientHandshake();
            // 包装成TLS记录格式
            return $this->messageHandler->wrapRecord(22, $handshakeMessage); // 22 = handshake
        }
        
        // 服务器等待 ClientHello
        return '';
    }
    
    /**
     * 处理接收到的握手数据
     * 
     * @param string $data 接收到的握手数据
     * @param string $encryptionLevel 加密级别
     * @return array 包含响应数据和新的加密级别
     */
    public function processHandshakeData(string $data, string $encryptionLevel): array
    {
        $responses = [];
        $newLevel = $encryptionLevel;
        
        // 解析握手消息
        $messages = $this->messageHandler->parseHandshakeData($data);
        
        foreach ($messages as $message) {
            // 根据加密级别解密消息（如果需要）
            if ($encryptionLevel !== 'initial') {
                $message['data'] = $this->cryptoManager->decrypt(
                    $message['data'],
                    $encryptionLevel,
                    $this->buildAssociatedData($message['type'])
                );
            }
            
            // 处理消息并获取响应
            $response = $this->stateMachine->processMessage($message['data']);
            
            if ($response) {
                // 检查是否需要切换加密级别
                $newLevel = $this->determineEncryptionLevel($message['type']);
                
                // 加密响应（如果需要）
                if ($newLevel !== 'initial') {
                    $response = $this->cryptoManager->encrypt(
                        $response,
                        $newLevel,
                        $this->buildAssociatedData(0) // 响应类型
                    );
                }
                
                // 包装成TLS记录格式
                $wrappedResponse = $this->messageHandler->wrapRecord(22, $response); // 22 = handshake
                
                $responses[] = [
                    'data' => $wrappedResponse,
                    'level' => $newLevel,
                ];
            }
            
            // 更新密钥（如果需要）
            $this->updateKeysIfNeeded($message['type']);
        }
        
        return [
            'responses' => $responses,
            'newLevel' => $newLevel,
            'isComplete' => $this->stateMachine->isComplete(),
        ];
    }
    
    /**
     * 根据消息类型确定加密级别
     */
    private function determineEncryptionLevel(int $messageType): string
    {
        return match ($messageType) {
            HandshakeStateMachine::MSG_CLIENT_HELLO,
            HandshakeStateMachine::MSG_SERVER_HELLO => 'initial',
            
            HandshakeStateMachine::MSG_ENCRYPTED_EXTENSIONS,
            HandshakeStateMachine::MSG_CERTIFICATE,
            HandshakeStateMachine::MSG_CERTIFICATE_VERIFY,
            HandshakeStateMachine::MSG_FINISHED => 'handshake',
            
            default => 'application',
        };
    }
    
    /**
     * 根据握手进度更新密钥
     */
    private function updateKeysIfNeeded(int $messageType): void
    {
        switch ($messageType) {
            case HandshakeStateMachine::MSG_SERVER_HELLO:
                // 派生握手密钥
                $this->deriveHandshakeSecrets();
                break;
                
            case HandshakeStateMachine::MSG_FINISHED:
                // 派生应用密钥
                $this->deriveApplicationSecrets();
                break;
        }
    }
    
    /**
     * 派生握手密钥
     */
    private function deriveHandshakeSecrets(): void
    {
        // 从状态机获取共享密钥（这里简化处理）
        $sharedSecret = random_bytes(32); // 实际应该从 ECDHE 计算
        
        // 使用 KeyScheduler 派生密钥
        $this->keyScheduler->setEarlySecret($this->psk ?? '');
        $transcriptHash = hash('sha256', $this->transcriptBuffer, true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);
        
        // 设置到 CryptoManager
        $this->cryptoManager->setHandshakeSecrets(
            $this->keyScheduler->getHandshakeKey(false), // client
            $this->keyScheduler->getHandshakeKey(true)   // server
        );
        
        $this->handshakeSecret = $this->keyScheduler->getHandshakeKey(true);
    }
    
    /**
     * 派生应用密钥
     */
    private function deriveApplicationSecrets(): void
    {
        if (!$this->handshakeSecret) {
            throw new \RuntimeException("握手密钥未设置");
        }
        
        // 派生主密钥
        $this->masterSecret = $this->keyScheduler->deriveMasterSecret();
        
        // 派生应用流量密钥
        $transcriptHash = $this->getTranscriptHash();
        $this->keyScheduler->deriveApplicationSecrets($transcriptHash);
        
        // 设置到 CryptoManager
        $this->cryptoManager->setApplicationSecrets(
            $this->keyScheduler->getApplicationKey(false), // client
            $this->keyScheduler->getApplicationKey(true)   // server
        );
    }
    
    /**
     * 构建关联数据（用于 AEAD）
     */
    private function buildAssociatedData(int $messageType): string
    {
        // 简化实现，实际应该包含更多信息
        return pack('C', $messageType);
    }
    
    /**
     * 获取转录哈希
     */
    public function getTranscriptHash(): string
    {
        // 从状态机获取
        return hash('sha256', $this->transcriptBuffer, true);
    }
    
    /**
     * 获取协商的传输参数
     */
    public function getNegotiatedParameters(): ?TransportParameters
    {
        return $this->stateMachine->getNegotiatedParameters();
    }
    
    /**
     * 获取当前加密级别
     */
    public function getCurrentEncryptionLevel(): string
    {
        return $this->cryptoManager->getCurrentLevel();
    }
    
    /**
     * 检查握手是否完成
     */
    public function isHandshakeComplete(): bool
    {
        return $this->stateMachine->isComplete();
    }
    
    /**
     * 设置 PSK（预共享密钥）用于 0-RTT
     */
    public function setPSK(string $psk, string $identity): void
    {
        $this->psk = $psk;
        $this->pskIdentity = $identity;
        $this->keyScheduler->setEarlySecret($psk);
    }
    
    /**
     * 导出密钥材料
     * 支持两种调用方式：
     * - exportKeyingMaterial($label, $length) 
     * - exportKeyingMaterial($label, $context, $length)
     */
    public function exportKeyingMaterial(string $label, $arg2 = null, ?int $length = null): string
    {
        if (!$this->masterSecret) {
            throw new \RuntimeException("主密钥未设置");
        }
        
        // 根据参数个数确定调用方式
        if ($length === null) {
            // 两个参数：exportKeyingMaterial($label, $length)
            $actualLength = (int)$arg2;
            $context = $this->getTranscriptHash();
        } else {
            // 三个参数：exportKeyingMaterial($label, $context, $length)
            $context = (string)$arg2;
            $actualLength = $length;
        }
        
        return $this->keyScheduler->exportKeyingMaterial(
            $this->masterSecret,
            $label,
            $context,
            $actualLength
        );
    }
    
    /**
     * 更新流量密钥
     */
    public function updateTrafficKeys(): void
    {
        $this->cryptoManager->updateKeys();
    }
    
    /**
     * 获取会话票据（用于会话恢复）
     */
    public function getSessionTicket(): ?string
    {
        if (!$this->masterSecret) {
            return null;
        }
        
        // 创建会话票据
        $ticket = [
            'version' => 0x0304, // TLS 1.3
            'cipher_suite' => $this->cryptoManager->getCipherInfo()['name'] ?? '',
            'master_secret' => base64_encode($this->masterSecret),
            'timestamp' => time(),
            'lifetime' => 7200, // 2 小时
        ];
        
        return base64_encode(serialize($ticket));
    }
    
    /**
     * 恢复会话
     */
    public function resumeSession(string $ticket): bool
    {
        try {
            $data = unserialize(base64_decode($ticket));
            
            if ($data['version'] !== 0x0304 || time() - $data['timestamp'] > $data['lifetime']) {
                return false;
            }
            
            $this->masterSecret = base64_decode($data['master_secret']);
            $this->setPSK($this->masterSecret, $ticket);
            
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * 获取调试信息
     */
    public function getDebugInfo(): array
    {
        return [
            'state' => $this->stateMachine->getCurrentState(),
            'is_server' => $this->isServer,
            'encryption_level' => $this->cryptoManager->getCurrentLevel(),
            'handshake_complete' => $this->stateMachine->isComplete(),
            'has_psk' => $this->psk !== null,
            'negotiated_params' => $this->getNegotiatedParameters()?->toArray(),
        ];
    }
    
    /**
     * 获取统计信息
     */
    public function getStatistics(): array
    {
        return [
            'messages_processed' => count($this->receivedMessages),
            'bytes_processed' => strlen($this->transcriptBuffer),
            'current_state' => $this->stateMachine->getCurrentState(),
            'handshake_complete' => $this->stateMachine->isComplete(),
            'encryption_level' => $this->cryptoManager->getCurrentLevel(),
            'pending_messages' => count($this->pendingMessages),
        ];
    }
    
    /**
     * 更新密钥
     */
    public function updateKeys(): void
    {
        $this->updateTrafficKeys();
    }
    
    /**
     * 重置握手状态
     */
    public function reset(): void
    {
        $this->stateMachine->reset();
        $this->pendingMessages = [];
        $this->receivedMessages = [];
        $this->transcriptBuffer = '';
        $this->handshakeSecret = null;
        $this->masterSecret = null;
        $this->psk = null;
        $this->pskIdentity = null;
    }
    
    /**
     * 设置 PSK（简化版本，单参数）
     */
    public function setPSKSimple(string $psk): void
    {
        $this->setPSK($psk, '');
    }
    
    
    
    /**
     * 处理消息（简化签名）
     */
    public function processMessage(string $message): array
    {
        try {
            return $this->processHandshakeData($message, 'initial');
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
    
    /**
     * 设置传输参数
     */
    public function setTransportParameters(TransportParameters $params): void
    {
        $this->localParams = $params;
    }
    
    /**
     * 设置证书验证器
     */
    public function setCertificateValidator(CertificateValidator $validator): void
    {
        $this->certValidator = $validator;
    }
} 