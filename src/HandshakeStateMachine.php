<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS;

use Tourze\QUIC\TLS\Message\Certificate;
use Tourze\QUIC\TLS\Message\CertificateVerify;
use Tourze\QUIC\TLS\Message\ClientHello;
use Tourze\QUIC\TLS\Message\EncryptedExtensions;
use Tourze\QUIC\TLS\Message\Finished;
use Tourze\QUIC\TLS\Message\ServerHello;

/**
 * TLS 1.3握手状态机
 * 
 * 根据RFC 8446实现TLS 1.3握手流程
 */
class HandshakeStateMachine
{
    // 握手状态常量
    public const STATE_INITIAL = 'initial';
    public const STATE_WAIT_SERVER_HELLO = 'wait_server_hello';
    public const STATE_WAIT_ENCRYPTED_EXTENSIONS = 'wait_encrypted_extensions';
    public const STATE_WAIT_CERTIFICATE = 'wait_certificate';
    public const STATE_WAIT_CERTIFICATE_VERIFY = 'wait_certificate_verify';
    public const STATE_WAIT_FINISHED = 'wait_finished';
    public const STATE_WAIT_CLIENT_FINISHED = 'wait_client_finished';
    public const STATE_ESTABLISHED = 'established';
    public const STATE_ERROR = 'error';

    // 握手消息类型
    public const MSG_CLIENT_HELLO = 0x01;
    public const MSG_SERVER_HELLO = 0x02;
    public const MSG_ENCRYPTED_EXTENSIONS = 0x08;
    public const MSG_CERTIFICATE = 0x0b;
    public const MSG_CERTIFICATE_VERIFY = 0x0f;
    public const MSG_FINISHED = 0x14;

    private string $currentState = self::STATE_INITIAL;
    private bool $isServer;
    private array $transcriptBuffer = [];
    private ?KeyScheduler $keyScheduler = null;
    private ?TransportParameters $localParams = null;
    private ?TransportParameters $peerParams = null;
    private ?CertificateValidator $certValidator = null;

    public function __construct(
        bool $isServer,
        ?TransportParameters $localParams = null,
        ?CertificateValidator $certValidator = null
    ) {
        $this->isServer = $isServer;
        $this->localParams = $localParams ?? new TransportParameters();
        $this->certValidator = $certValidator ?? new CertificateValidator();
        $this->keyScheduler = new KeyScheduler();
    }

    /**
     * 处理握手消息
     *
     * @param string $message 握手消息数据
     * @return string 响应消息（如果有）
     * @throws \InvalidArgumentException 消息格式错误
     * @throws \RuntimeException 状态错误
     */
    public function processMessage(string $message): string
    {
        if (strlen($message) < 4) {
            throw new \InvalidArgumentException('握手消息太短');
        }

        $type = ord($message[0]);
        $length = unpack('N', "\x00" . substr($message, 1, 3))[1];
        
        if (strlen($message) < 4 + $length) {
            throw new \InvalidArgumentException('握手消息长度不匹配');
        }

        $payload = substr($message, 4, $length);
        
        // 添加到转录缓冲区
        $this->addToTranscript($type, $payload);

        return $this->handleMessage($type, $payload);
    }

    /**
     * 处理具体的握手消息
     */
    private function handleMessage(int $type, string $payload): string
    {
        return match (true) {
            $type === self::MSG_CLIENT_HELLO => $this->handleClientHello($payload),
            $type === self::MSG_SERVER_HELLO => $this->handleServerHello($payload),
            $type === self::MSG_ENCRYPTED_EXTENSIONS => $this->handleEncryptedExtensions($payload),
            $type === self::MSG_CERTIFICATE => $this->handleCertificate($payload),
            $type === self::MSG_CERTIFICATE_VERIFY => $this->handleCertificateVerify($payload),
            $type === self::MSG_FINISHED => $this->handleFinished($payload),
            default => throw new \InvalidArgumentException("不支持的握手消息类型: {$type}"),
        };
    }

    /**
     * 处理ClientHello消息
     */
    private function handleClientHello(string $payload): string
    {
        if ($this->currentState !== self::STATE_INITIAL || !$this->isServer) {
            throw new \RuntimeException('状态错误：不能处理ClientHello');
        }

        $clientHello = ClientHello::decode($payload);
        
        // 提取传输参数
        $this->peerParams = $clientHello->getTransportParameters();
        
        // 更新状态并生成响应
        $this->currentState = self::STATE_WAIT_CLIENT_FINISHED;
        
        $responses = '';
        
        // ServerHello
        $serverHello = new ServerHello($this->localParams);
        $responses .= $this->wrapMessage(self::MSG_SERVER_HELLO, $serverHello->encode());
        
        // EncryptedExtensions
        $encryptedExt = new EncryptedExtensions($this->localParams);
        $responses .= $this->wrapMessage(self::MSG_ENCRYPTED_EXTENSIONS, $encryptedExt->encode());
        
        // Certificate (如果需要)
        if ($this->certValidator->hasServerCertificate()) {
            $certificate = new Certificate($this->certValidator->getServerCertificate());
            $responses .= $this->wrapMessage(self::MSG_CERTIFICATE, $certificate->encode());
            
            // CertificateVerify
            $transcriptHash = $this->computeTranscriptHash();
            $certVerify = new CertificateVerify($this->certValidator->signTranscript($transcriptHash));
            $responses .= $this->wrapMessage(self::MSG_CERTIFICATE_VERIFY, $certVerify->encode());
        }
        
        // Finished
        $verifyData = $this->keyScheduler->computeFinishedMAC($this->computeTranscriptHash(), true);
        $finished = new Finished($verifyData);
        $responses .= $this->wrapMessage(self::MSG_FINISHED, $finished->encode());

        return $responses;
    }

    /**
     * 处理ServerHello消息
     */
    private function handleServerHello(string $payload): string
    {
        if ($this->currentState !== self::STATE_WAIT_SERVER_HELLO || $this->isServer) {
            throw new \RuntimeException('状态错误：不能处理ServerHello');
        }

        $serverHello = ServerHello::decode($payload);
        $this->currentState = self::STATE_WAIT_ENCRYPTED_EXTENSIONS;
        
        return '';
    }

    /**
     * 处理EncryptedExtensions消息
     */
    private function handleEncryptedExtensions(string $payload): string
    {
        if ($this->currentState !== self::STATE_WAIT_ENCRYPTED_EXTENSIONS || $this->isServer) {
            throw new \RuntimeException('状态错误：不能处理EncryptedExtensions');
        }

        $encryptedExt = EncryptedExtensions::decode($payload);
        $this->peerParams = $encryptedExt->getTransportParameters();
        $this->currentState = self::STATE_WAIT_CERTIFICATE;
        
        return '';
    }

    /**
     * 处理Certificate消息
     */
    private function handleCertificate(string $payload): string
    {
        if ($this->currentState !== self::STATE_WAIT_CERTIFICATE || $this->isServer) {
            throw new \RuntimeException('状态错误：不能处理Certificate');
        }

        $certificate = Certificate::decode($payload);
        
        // 验证证书
        if (!$this->certValidator->validateCertificate($certificate->getCertificateChain())) {
            $this->currentState = self::STATE_ERROR;
            throw new \RuntimeException('证书验证失败');
        }
        
        $this->currentState = self::STATE_WAIT_CERTIFICATE_VERIFY;
        
        return '';
    }

    /**
     * 处理CertificateVerify消息
     */
    private function handleCertificateVerify(string $payload): string
    {
        if ($this->currentState !== self::STATE_WAIT_CERTIFICATE_VERIFY || $this->isServer) {
            throw new \RuntimeException('状态错误：不能处理CertificateVerify');
        }

        $certVerify = CertificateVerify::decode($payload);
        
        // 验证签名
        $transcriptHash = $this->computeTranscriptHash();
        if (!$this->certValidator->verifyTranscriptSignature($transcriptHash, $certVerify->getSignature())) {
            $this->currentState = self::STATE_ERROR;
            throw new \RuntimeException('证书签名验证失败');
        }
        
        $this->currentState = self::STATE_WAIT_FINISHED;
        
        return '';
    }

    /**
     * 处理Finished消息
     */
    private function handleFinished(string $payload): string
    {
        $finished = Finished::decode($payload);
        
        if ($this->isServer) {
            if ($this->currentState !== self::STATE_WAIT_CLIENT_FINISHED) {
                throw new \RuntimeException('状态错误：不能处理客户端Finished');
            }
            
            // 验证客户端Finished消息
            $expectedVerifyData = $this->keyScheduler->computeFinishedMAC($this->computeTranscriptHash(), false);
            if (!hash_equals($expectedVerifyData, $finished->getVerifyData())) {
                $this->currentState = self::STATE_ERROR;
                throw new \RuntimeException('客户端Finished验证失败');
            }
            
            $this->currentState = self::STATE_ESTABLISHED;
        } else {
            if ($this->currentState !== self::STATE_WAIT_FINISHED) {
                throw new \RuntimeException('状态错误：不能处理服务端Finished');
            }
            
            // 验证服务端Finished消息
            $expectedVerifyData = $this->keyScheduler->computeFinishedMAC($this->computeTranscriptHash(), true);
            if (!hash_equals($expectedVerifyData, $finished->getVerifyData())) {
                $this->currentState = self::STATE_ERROR;
                throw new \RuntimeException('服务端Finished验证失败');
            }
            
            // 发送客户端Finished
            $clientVerifyData = $this->keyScheduler->computeFinishedMAC($this->computeTranscriptHash(), false);
            $clientFinished = new Finished($clientVerifyData);
            $response = $this->wrapMessage(self::MSG_FINISHED, $clientFinished->encode());
            
            $this->currentState = self::STATE_ESTABLISHED;
            
            return $response;
        }
        
        return '';
    }

    /**
     * 开始客户端握手
     */
    public function startClientHandshake(): string
    {
        if ($this->currentState !== self::STATE_INITIAL || $this->isServer) {
            throw new \RuntimeException('状态错误：不能开始客户端握手');
        }

        $clientHello = new ClientHello($this->localParams);
        $this->currentState = self::STATE_WAIT_SERVER_HELLO;
        
        return $this->wrapMessage(self::MSG_CLIENT_HELLO, $clientHello->encode());
    }

    /**
     * 检查握手是否完成
     */
    public function isComplete(): bool
    {
        return $this->currentState === self::STATE_ESTABLISHED;
    }

    /**
     * 获取当前状态
     */
    public function getCurrentState(): string
    {
        return $this->currentState;
    }

    /**
     * 获取协商的传输参数
     */
    public function getNegotiatedParameters(): ?TransportParameters
    {
        return $this->peerParams;
    }

    /**
     * 添加消息到转录缓冲区
     */
    private function addToTranscript(int $type, string $payload): void
    {
        $this->transcriptBuffer[] = [
            'type' => $type,
            'payload' => $payload,
        ];
    }

    /**
     * 计算转录哈希
     */
    private function computeTranscriptHash(): string
    {
        $context = hash_init('sha256');
        
        foreach ($this->transcriptBuffer as $message) {
            $data = pack('C', $message['type']) .
                    substr(pack('N', strlen($message['payload'])), 1) .
                    $message['payload'];
            hash_update($context, $data);
        }
        
        return hash_final($context, true);
    }

    /**
     * 包装握手消息
     */
    private function wrapMessage(int $type, string $payload): string
    {
        $this->addToTranscript($type, $payload);
        
        return pack('C', $type) .
               substr(pack('N', strlen($payload)), 1) .
               $payload;
    }
} 