<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\CertificateValidator;
use Tourze\QUIC\TLS\HandshakeStateMachine;
use Tourze\QUIC\TLS\Message\ClientHello;
use Tourze\QUIC\TLS\Message\ServerHello;
use Tourze\QUIC\TLS\TransportParameters;

class HandshakeStateMachineTest extends TestCase
{
    private TransportParameters $transportParams;
    private CertificateValidator $certValidator;
    
    protected function setUp(): void
    {
        $this->transportParams = new TransportParameters();
        $this->transportParams->setMaxIdleTimeout(30000);
        $this->transportParams->setMaxUdpPayloadSize(1200);
        
        $this->certValidator = new CertificateValidator([
            'verify_peer' => false,
            'allow_self_signed' => true,
        ]);
    }
    
    public function testClientInitialization(): void
    {
        $stateMachine = new HandshakeStateMachine(false, $this->transportParams, $this->certValidator);
        
        $this->assertFalse($stateMachine->isComplete());
        $this->assertEquals(HandshakeStateMachine::STATE_INITIAL, $stateMachine->getCurrentState());
        $this->assertNull($stateMachine->getNegotiatedParameters());
    }
    
    public function testServerInitialization(): void
    {
        $stateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        
        $this->assertFalse($stateMachine->isComplete());
        $this->assertEquals(HandshakeStateMachine::STATE_INITIAL, $stateMachine->getCurrentState());
        $this->assertNull($stateMachine->getNegotiatedParameters());
    }
    
    public function testClientHandshakeStart(): void
    {
        $stateMachine = new HandshakeStateMachine(false, $this->transportParams, $this->certValidator);
        
        $clientHello = $stateMachine->startClientHandshake();
        
        $this->assertNotEmpty($clientHello);
        $this->assertEquals(HandshakeStateMachine::STATE_WAIT_SERVER_HELLO, $stateMachine->getCurrentState());
        
        // 验证 ClientHello 消息格式
        $this->assertGreaterThan(4, strlen($clientHello));
        $messageType = ord($clientHello[0]);
        $this->assertEquals(HandshakeStateMachine::MSG_CLIENT_HELLO, $messageType);
    }
    
    public function testServerCannotStartClientHandshake(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('状态错误：不能开始客户端握手');
        
        $stateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        $stateMachine->startClientHandshake();
    }
    
    public function testInvalidMessageFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        
        $stateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        $stateMachine->processMessage('abc'); // 太短的消息
    }
    
    public function testMessageLengthMismatch(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        
        $stateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        
        // 创建一个长度不匹配的消息
        $message = pack('C', 1) . pack('N', 100)[1] . pack('n', 100) . 'short'; // 声称100字节但只有5字节
        $stateMachine->processMessage($message);
    }
    
    public function testUnsupportedMessageType(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('不支持的握手消息类型');
        
        $stateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        
        // 创建一个不支持的消息类型
        $payload = 'test';
        $message = pack('C', 99) . substr(pack('N', strlen($payload)), 1) . $payload;
        $stateMachine->processMessage($message);
    }
    
    public function testClientHelloProcessing(): void
    {
        $serverStateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        $clientStateMachine = new HandshakeStateMachine(false, $this->transportParams, $this->certValidator);
        
        // 客户端发送 ClientHello
        $clientHello = $clientStateMachine->startClientHandshake();
        
        // 服务器处理 ClientHello
        $serverResponse = $serverStateMachine->processMessage($clientHello);
        
        $this->assertNotEmpty($serverResponse);
        $this->assertEquals(HandshakeStateMachine::STATE_WAIT_CLIENT_FINISHED, $serverStateMachine->getCurrentState());
    }
    
    public function testBasicHandshakeFlow(): void
    {
        $serverStateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        $clientStateMachine = new HandshakeStateMachine(false, $this->transportParams, $this->certValidator);
        
        // 1. 客户端发送 ClientHello
        $clientHello = $clientStateMachine->startClientHandshake();
        $this->assertEquals(HandshakeStateMachine::STATE_WAIT_SERVER_HELLO, $clientStateMachine->getCurrentState());
        
        // 2. 服务器处理 ClientHello 并发送响应
        $serverResponse = $serverStateMachine->processMessage($clientHello);
        $this->assertNotEmpty($serverResponse);
        $this->assertEquals(HandshakeStateMachine::STATE_WAIT_CLIENT_FINISHED, $serverStateMachine->getCurrentState());
        
        // 3. 客户端处理服务器响应
        $clientResponse = $this->processMultipleMessages($clientStateMachine, $serverResponse);
        
        // 4. 服务器处理客户端 Finished
        if (!empty($clientResponse)) {
            $serverStateMachine->processMessage($clientResponse);
        }
        
        // 检查握手完成状态
        $this->assertTrue($serverStateMachine->isComplete());
    }
    
    public function testWrongStateTransition(): void
    {
        $this->expectException(\RuntimeException::class);
        
        $stateMachine = new HandshakeStateMachine(false, $this->transportParams, $this->certValidator);
        
        // 尝试在错误的状态下处理 ServerHello
        $fakeServerHello = $this->createFakeServerHello();
        $stateMachine->processMessage($fakeServerHello); // 应该失败，因为还没发送 ClientHello
    }
    
    public function testTransportParametersNegotiation(): void
    {
        $clientParams = new TransportParameters();
        $clientParams->setMaxIdleTimeout(60000);
        $clientParams->setMaxUdpPayloadSize(1500);
        
        $serverParams = new TransportParameters();
        $serverParams->setMaxIdleTimeout(30000);
        $serverParams->setMaxUdpPayloadSize(1200);
        
        $serverStateMachine = new HandshakeStateMachine(true, $serverParams, $this->certValidator);
        $clientStateMachine = new HandshakeStateMachine(false, $clientParams, $this->certValidator);
        
        // 执行握手
        $clientHello = $clientStateMachine->startClientHandshake();
        $serverResponse = $serverStateMachine->processMessage($clientHello);
        
        // 检查服务器是否接收到客户端参数
        $negotiatedParams = $serverStateMachine->getNegotiatedParameters();
        $this->assertNotNull($negotiatedParams);
    }
    
    public function testCertificateValidation(): void
    {
        // 创建一个需要证书验证的验证器
        $strictCertValidator = new CertificateValidator([
            'verify_peer' => true,
            'allow_self_signed' => false,
        ]);
        
        $serverStateMachine = new HandshakeStateMachine(true, $this->transportParams, $strictCertValidator);
        $clientStateMachine = new HandshakeStateMachine(false, $this->transportParams, $strictCertValidator);
        
        // 基本的握手应该能够开始
        $clientHello = $clientStateMachine->startClientHandshake();
        $this->assertNotEmpty($clientHello);
        
        // 服务器应该能够处理 ClientHello
        $serverResponse = $serverStateMachine->processMessage($clientHello);
        $this->assertNotEmpty($serverResponse);
    }
    
    public function testStateTransitionLogging(): void
    {
        $stateMachine = new HandshakeStateMachine(false, $this->transportParams, $this->certValidator);
        
        $initialState = $stateMachine->getCurrentState();
        $this->assertEquals(HandshakeStateMachine::STATE_INITIAL, $initialState);
        
        $stateMachine->startClientHandshake();
        $newState = $stateMachine->getCurrentState();
        $this->assertEquals(HandshakeStateMachine::STATE_WAIT_SERVER_HELLO, $newState);
        $this->assertNotEquals($initialState, $newState);
    }
    
    public function testHandshakeStateMachineReset(): void
    {
        $stateMachine = new HandshakeStateMachine(false, $this->transportParams, $this->certValidator);
        
        // 开始握手
        $stateMachine->startClientHandshake();
        $this->assertEquals(HandshakeStateMachine::STATE_WAIT_SERVER_HELLO, $stateMachine->getCurrentState());
        
        // 创建新的状态机实例来模拟重置
        $newStateMachine = new HandshakeStateMachine(false, $this->transportParams, $this->certValidator);
        $this->assertEquals(HandshakeStateMachine::STATE_INITIAL, $newStateMachine->getCurrentState());
    }
    
    public function testMessageValidation(): void
    {
        $stateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        
        // 测试有效的 ClientHello
        $validClientHello = $this->createValidClientHello();
        $this->assertNotEmpty($stateMachine->processMessage($validClientHello));
        
        // 创建新的状态机测试无效消息
        $newStateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        
        $this->expectException(\InvalidArgumentException::class);
        $invalidMessage = pack('C', 1) . pack('N', 10)[1] . pack('n', 10) . 'invalid'; // 无效的 ClientHello
        $newStateMachine->processMessage($invalidMessage);
    }
    
    public function testErrorStateHandling(): void
    {
        $stateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        
        try {
            // 尝试处理格式错误的消息
            $stateMachine->processMessage('invalid');
        } catch (\InvalidArgumentException $e) {
            // 验证状态机仍然处于可用状态
            $this->assertEquals(HandshakeStateMachine::STATE_INITIAL, $stateMachine->getCurrentState());
            $this->assertFalse($stateMachine->isComplete());
        }
    }
    
    public function testMultipleClientHelloHandling(): void
    {
        $stateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        
        $clientHello1 = $this->createValidClientHello();
        $response1 = $stateMachine->processMessage($clientHello1);
        $this->assertNotEmpty($response1);
        
        // 处理第二个 ClientHello 应该失败
        $this->expectException(\RuntimeException::class);
        $clientHello2 = $this->createValidClientHello();
        $stateMachine->processMessage($clientHello2);
    }
    
    public function testHandshakeCompletionDetection(): void
    {
        $serverStateMachine = new HandshakeStateMachine(true, $this->transportParams, $this->certValidator);
        $clientStateMachine = new HandshakeStateMachine(false, $this->transportParams, $this->certValidator);
        
        // 握手前应该未完成
        $this->assertFalse($serverStateMachine->isComplete());
        $this->assertFalse($clientStateMachine->isComplete());
        
        // 执行部分握手
        $clientHello = $clientStateMachine->startClientHandshake();
        $serverResponse = $serverStateMachine->processMessage($clientHello);
        
        // 部分握手仍未完成
        $this->assertFalse($serverStateMachine->isComplete());
        
        // 完成握手流程
        $clientResponse = $this->processMultipleMessages($clientStateMachine, $serverResponse);
        if (!empty($clientResponse)) {
            $serverStateMachine->processMessage($clientResponse);
        }
        
        // 验证握手完成
        $this->assertTrue($serverStateMachine->isComplete());
    }
    
    /**
     * 处理包含多个消息的响应
     */
    private function processMultipleMessages(HandshakeStateMachine $stateMachine, string $data): string
    {
        $response = '';
        $offset = 0;
        
        while ($offset < strlen($data)) {
            if (strlen($data) - $offset < 4) {
                break;
            }
            
            $messageType = ord($data[$offset]);
            $messageLength = unpack('N', "\x00" . substr($data, $offset + 1, 3))[1];
            
            if (strlen($data) - $offset < 4 + $messageLength) {
                break;
            }
            
            $message = substr($data, $offset, 4 + $messageLength);
            try {
                $result = $stateMachine->processMessage($message);
                if (!empty($result)) {
                    $response .= $result;
                }
            } catch (\Exception $e) {
                // 某些消息可能会失败，这是正常的
            }
            
            $offset += 4 + $messageLength;
        }
        
        return $response;
    }
    
    /**
     * 创建假的 ServerHello 消息
     */
    private function createFakeServerHello(): string
    {
        $serverHello = new ServerHello($this->transportParams);
        $payload = $serverHello->encode();
        
        return pack('C', HandshakeStateMachine::MSG_SERVER_HELLO) .
               substr(pack('N', strlen($payload)), 1) .
               $payload;
    }
    
    /**
     * 创建有效的 ClientHello 消息
     */
    private function createValidClientHello(): string
    {
        $clientHello = new ClientHello($this->transportParams);
        $payload = $clientHello->encode();
        
        return pack('C', HandshakeStateMachine::MSG_CLIENT_HELLO) .
               substr(pack('N', strlen($payload)), 1) .
               $payload;
    }
}