<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Exception\InvalidParameterException;
use Tourze\QUIC\TLS\Message\ClientHello;
use Tourze\QUIC\TLS\TransportParameters;

/**
 * @internal
 */
#[CoversClass(ClientHello::class)]
final class ClientHelloTest extends TestCase
{
    public function testConstructorWithoutParameters(): void
    {
        $clientHello = new ClientHello();
        $this->assertInstanceOf(ClientHello::class, $clientHello);
        $this->assertInstanceOf(TransportParameters::class, $clientHello->getTransportParameters());
    }

    public function testConstructorWithTransportParameters(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
        ]);
        $clientHello = new ClientHello($params);
        $this->assertSame($params, $clientHello->getTransportParameters());
    }

    public function testEncodeGeneratesValidMessage(): void
    {
        $clientHello = new ClientHello();
        $encoded = $clientHello->encode();
        $this->assertNotEmpty($encoded);
        $this->assertGreaterThan(100, strlen($encoded)); // ClientHello应该相当大
    }

    public function testGetRandomReturns32Bytes(): void
    {
        $clientHello = new ClientHello();
        $random = $clientHello->getRandom();
        $this->assertEquals(32, strlen($random));
    }

    public function testGetSessionIdReturns32Bytes(): void
    {
        $clientHello = new ClientHello();
        $sessionId = $clientHello->getSessionId();
        $this->assertEquals(32, strlen($sessionId));
    }

    public function testGetCipherSuitesReturnsDefaultSuites(): void
    {
        $clientHello = new ClientHello();
        $cipherSuites = $clientHello->getCipherSuites();
        $this->assertNotEmpty($cipherSuites);
        $this->assertContains(0x1301, $cipherSuites); // TLS_AES_128_GCM_SHA256
        $this->assertContains(0x1302, $cipherSuites); // TLS_AES_256_GCM_SHA384
        $this->assertContains(0x1303, $cipherSuites); // TLS_CHACHA20_POLY1305_SHA256
    }

    public function testGetExtensionsReturnsExtensions(): void
    {
        $clientHello = new ClientHello();
        $extensions = $clientHello->getExtensions();
        $this->assertNotEmpty($extensions);
    }

    public function testGetExtensionWithValidType(): void
    {
        $clientHello = new ClientHello();
        $sniExtension = $clientHello->getExtension(0x0000); // SNI
        $this->assertNotNull($sniExtension);
        $this->assertNotEmpty($sniExtension);
    }

    public function testGetExtensionWithInvalidType(): void
    {
        $clientHello = new ClientHello();
        $unknownExtension = $clientHello->getExtension(0x9999);
        $this->assertNull($unknownExtension);
    }

    public function testSetRandom(): void
    {
        $clientHello = new ClientHello();
        $customRandom = str_repeat('a', 32);
        $clientHello->setRandom($customRandom);
        $this->assertEquals($customRandom, $clientHello->getRandom());
    }

    public function testSetCipherSuites(): void
    {
        $clientHello = new ClientHello();
        $customSuites = [0x1301, 0x1302];
        $clientHello->setCipherSuites($customSuites);
        $this->assertEquals($customSuites, $clientHello->getCipherSuites());
    }

    public function testSetExtensions(): void
    {
        $clientHello = new ClientHello();
        $customExtensions = [0x0000 => 'test-extension'];
        $clientHello->setExtensions($customExtensions);
        $this->assertEquals($customExtensions, $clientHello->getExtensions());
    }

    public function testSetTransportParameters(): void
    {
        $clientHello = new ClientHello();
        $newParams = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 60000,
        ]);
        $clientHello->setTransportParameters($newParams);
        $this->assertSame($newParams, $clientHello->getTransportParameters());
    }

    public function testEncodeAndDecodeRoundTrip(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
        ]);
        $clientHello = new ClientHello($params);

        $encoded = $clientHello->encode();
        $decoded = ClientHello::decode($encoded);

        $this->assertEquals($clientHello->getRandom(), $decoded->getRandom());
        $this->assertEquals($clientHello->getSessionId(), $decoded->getSessionId());
        $this->assertEquals($clientHello->getCipherSuites(), $decoded->getCipherSuites());
        $this->assertInstanceOf(TransportParameters::class, $decoded->getTransportParameters());
    }

    public function testDecodeWithMinimalData(): void
    {
        // 构造最小的有效ClientHello数据
        $data = '';
        $data .= "\x03\x04"; // 协议版本
        $data .= str_repeat('a', 32); // 随机数
        $data .= "\x00"; // 会话ID长度为0
        $data .= "\x00\x06"; // 密码套件长度
        $data .= pack('n', 0x1301); // TLS_AES_128_GCM_SHA256
        $data .= pack('n', 0x1302); // TLS_AES_256_GCM_SHA384
        $data .= pack('n', 0x1303); // TLS_CHACHA20_POLY1305_SHA256
        $data .= "\x01\x00"; // 压缩方法
        $data .= "\x00\x00"; // 扩展长度为0

        $decoded = ClientHello::decode($data);
        $this->assertInstanceOf(ClientHello::class, $decoded);
        $this->assertEquals(str_repeat('a', 32), $decoded->getRandom());
    }

    public function testDecodeWithInvalidDataThrowsException(): void
    {
        $this->expectException(InvalidParameterException::class);
        ClientHello::decode('invalid-data');
    }
}
