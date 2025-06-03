<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\CertificateValidator;
use Tourze\QUIC\TLS\HandshakeStateMachine;
use Tourze\QUIC\TLS\TransportParameters;

class HandshakeStateMachineTest extends TestCase
{
    public function testClientHandshakeInitialization(): void
    {
        $transportParams = new TransportParameters();
        $stateMachine = new HandshakeStateMachine(false, $transportParams);
        
        $this->assertEquals(HandshakeStateMachine::STATE_INITIAL, $stateMachine->getCurrentState());
        $this->assertFalse($stateMachine->isComplete());
    }

    public function testServerHandshakeInitialization(): void
    {
        $transportParams = new TransportParameters();
        $stateMachine = new HandshakeStateMachine(true, $transportParams);
        
        $this->assertEquals(HandshakeStateMachine::STATE_INITIAL, $stateMachine->getCurrentState());
        $this->assertFalse($stateMachine->isComplete());
    }

    public function testClientHandshakeStart(): void
    {
        $transportParams = new TransportParameters();
        $stateMachine = new HandshakeStateMachine(false, $transportParams);
        
        $clientHello = $stateMachine->startClientHandshake();
        
        $this->assertNotEmpty($clientHello);
        $this->assertEquals(HandshakeStateMachine::STATE_WAIT_SERVER_HELLO, $stateMachine->getCurrentState());
    }

    public function testInvalidMessageHandling(): void
    {
        $transportParams = new TransportParameters();
        $stateMachine = new HandshakeStateMachine(false, $transportParams);
        
        $this->expectException(\InvalidArgumentException::class);
        $stateMachine->processMessage('short');
    }

    public function testTransportParametersNegotiation(): void
    {
        $localParams = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
            TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE => 1200,
        ]);
        
        $stateMachine = new HandshakeStateMachine(false, $localParams);
        
        $this->assertInstanceOf(TransportParameters::class, $stateMachine->getNegotiatedParameters());
    }

    public function testStateTransitions(): void
    {
        $stateMachine = new HandshakeStateMachine(false);
        
        // 初始状态
        $this->assertEquals(HandshakeStateMachine::STATE_INITIAL, $stateMachine->getCurrentState());
        
        // 开始握手
        $stateMachine->startClientHandshake();
        $this->assertEquals(HandshakeStateMachine::STATE_WAIT_SERVER_HELLO, $stateMachine->getCurrentState());
    }

    public function testCertificateValidatorIntegration(): void
    {
        $certValidator = new CertificateValidator([
            'verify_peer' => false,
            'allow_self_signed' => true,
        ]);
        
        $stateMachine = new HandshakeStateMachine(false, null, $certValidator);
        
        $this->assertEquals(HandshakeStateMachine::STATE_INITIAL, $stateMachine->getCurrentState());
    }
} 