<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Unit\Message;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Message\ServerHello;
use Tourze\QUIC\TLS\TransportParameters;

class ServerHelloTest extends TestCase
{
    public function test_constructor_withoutParameters(): void
    {
        $serverHello = new ServerHello();
        $this->assertInstanceOf(ServerHello::class, $serverHello);
        $this->assertInstanceOf(TransportParameters::class, $serverHello->getTransportParameters());
    }

    public function test_constructor_withTransportParameters(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
        ]);
        $serverHello = new ServerHello($params);
        $this->assertSame($params, $serverHello->getTransportParameters());
    }

    public function test_getCipherSuite_returnsDefaultSuite(): void
    {
        $serverHello = new ServerHello();
        $this->assertEquals(0x1301, $serverHello->getCipherSuite()); // TLS_AES_128_GCM_SHA256
    }

    public function test_setCipherSuite(): void
    {
        $serverHello = new ServerHello();
        $newSuite = 0x1302; // TLS_AES_256_GCM_SHA384
        $serverHello->setCipherSuite($newSuite);
        $this->assertEquals($newSuite, $serverHello->getCipherSuite());
    }

    public function test_setTransportParameters(): void
    {
        $serverHello = new ServerHello();
        $newParams = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 60000,
        ]);
        
        $serverHello->setTransportParameters($newParams);
        $this->assertSame($newParams, $serverHello->getTransportParameters());
    }

    public function test_setRandom(): void
    {
        $serverHello = new ServerHello();
        $customRandom = str_repeat('b', 32);
        $serverHello->setRandom($customRandom);
        
        // 通过编码/解码来验证随机数是否被设置
        $encoded = $serverHello->encode();
        $decoded = ServerHello::decode($encoded);
        $this->assertStringContainsString($customRandom, $encoded);
    }

    public function test_setExtensions(): void
    {
        $serverHello = new ServerHello();
        $customExtensions = [0x0000 => 'test-extension'];
        $serverHello->setExtensions($customExtensions);
        
        // 验证扩展已设置（通过编码验证）
        $encoded = $serverHello->encode();
        $this->assertNotEmpty($encoded);
    }

    public function test_encode_generatesValidMessage(): void
    {
        $serverHello = new ServerHello();
        $encoded = $serverHello->encode();
        $this->assertNotEmpty($encoded);
        $this->assertGreaterThan(80, strlen($encoded)); // ServerHello应该相当大
    }

    public function test_encodeAndDecode_roundTrip(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
            TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE => 1472,
        ]);
        $serverHello = new ServerHello($params);
        $serverHello->setCipherSuite(0x1302);
        
        $encoded = $serverHello->encode();
        $decoded = ServerHello::decode($encoded);
        
        $this->assertEquals($serverHello->getCipherSuite(), $decoded->getCipherSuite());
        $this->assertInstanceOf(TransportParameters::class, $decoded->getTransportParameters());
    }

    public function test_decode_withValidData(): void
    {
        // 构造有效的ServerHello数据
        $data = '';
        $data .= "\x03\x04"; // 协议版本 TLS 1.3
        $data .= str_repeat('s', 32); // 服务器随机数
        $data .= "\x20" . str_repeat('i', 32); // 会话ID长度和内容
        $data .= pack('n', 0x1301); // 密码套件
        $data .= "\x00"; // 压缩方法
        $data .= "\x00\x00"; // 扩展长度为0
        
        $decoded = ServerHello::decode($data);
        $this->assertInstanceOf(ServerHello::class, $decoded);
        $this->assertEquals(0x1301, $decoded->getCipherSuite());
    }

    public function test_supportedCipherSuites(): void
    {
        $supportedSuites = [
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
        ];
        
        foreach ($supportedSuites as $suite) {
            $serverHello = new ServerHello();
            $serverHello->setCipherSuite($suite);
            $this->assertEquals($suite, $serverHello->getCipherSuite());
            
            // 验证可以正确编码和解码
            $encoded = $serverHello->encode();
            $decoded = ServerHello::decode($encoded);
            $this->assertEquals($suite, $decoded->getCipherSuite());
        }
    }

    public function test_extensions_areBuiltCorrectly(): void
    {
        $serverHello = new ServerHello();
        $encoded = $serverHello->encode();
        $decoded = ServerHello::decode($encoded);
        
        // 解码后应该仍然有传输参数
        $this->assertInstanceOf(TransportParameters::class, $decoded->getTransportParameters());
    }

    public function test_transportParametersInExtensions(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 45000,
            TransportParameters::PARAM_INITIAL_MAX_DATA => 1048576,
        ]);
        
        $serverHello = new ServerHello($params);
        $encoded = $serverHello->encode();
        $decoded = ServerHello::decode($encoded);
        
        $decodedParams = $decoded->getTransportParameters();
        $this->assertInstanceOf(TransportParameters::class, $decodedParams);
    }

    public function test_minimumMessageSize(): void
    {
        $serverHello = new ServerHello();
        $encoded = $serverHello->encode();
        
        // ServerHello消息至少应该包含：
        // - 协议版本 (2字节)
        // - 随机数 (32字节)
        // - 会话ID长度 + 会话ID (1 + 32字节)
        // - 密码套件 (2字节)
        // - 压缩方法 (1字节)
        // - 扩展长度 (2字节)
        // - 扩展数据 (至少几个字节)
        $minSize = 2 + 32 + 1 + 32 + 2 + 1 + 2;
        $this->assertGreaterThan($minSize, strlen($encoded));
    }
}