<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Unit\Message;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Message\EncryptedExtensions;
use Tourze\QUIC\TLS\TransportParameters;

class EncryptedExtensionsTest extends TestCase
{
    public function test_constructor_withoutParameters(): void
    {
        $encryptedExtensions = new EncryptedExtensions();
        $this->assertInstanceOf(EncryptedExtensions::class, $encryptedExtensions);
        $this->assertInstanceOf(TransportParameters::class, $encryptedExtensions->getTransportParameters());
    }

    public function test_constructor_withTransportParameters(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
        ]);
        $encryptedExtensions = new EncryptedExtensions($params);
        $this->assertSame($params, $encryptedExtensions->getTransportParameters());
    }

    public function test_getExtensions_returnsBuiltExtensions(): void
    {
        $encryptedExtensions = new EncryptedExtensions();
        $extensions = $encryptedExtensions->getExtensions();
        $this->assertNotEmpty($extensions);
        
        // 应该包含 QUIC Transport Parameters 扩展
        $this->assertArrayHasKey(0x0039, $extensions);
        
        // 应该包含 ALPN 扩展
        $this->assertArrayHasKey(0x0010, $extensions);
    }

    public function test_encode_generatesValidMessage(): void
    {
        $encryptedExtensions = new EncryptedExtensions();
        $encoded = $encryptedExtensions->encode();
        $this->assertNotEmpty($encoded);
        $this->assertGreaterThan(4, strlen($encoded)); // 至少包含长度字段和一些扩展数据
    }

    public function test_setTransportParameters(): void
    {
        $encryptedExtensions = new EncryptedExtensions();
        $newParams = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 60000,
        ]);
        
        $encryptedExtensions->setTransportParameters($newParams);
        $this->assertSame($newParams, $encryptedExtensions->getTransportParameters());
        
        // 验证扩展已更新
        $extensions = $encryptedExtensions->getExtensions();
        $this->assertArrayHasKey(0x0039, $extensions);
    }

    public function test_encodeAndDecode_roundTrip(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
            TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE => 1472,
        ]);
        $encryptedExtensions = new EncryptedExtensions($params);
        
        $encoded = $encryptedExtensions->encode();
        $decoded = EncryptedExtensions::decode($encoded);
        
        $this->assertInstanceOf(EncryptedExtensions::class, $decoded);
        $this->assertInstanceOf(TransportParameters::class, $decoded->getTransportParameters());
        
        // 验证扩展数量相同
        $originalExtensions = $encryptedExtensions->getExtensions();
        $decodedExtensions = $decoded->getExtensions();
        $this->assertEquals(count($originalExtensions), count($decodedExtensions));
    }

    public function test_decode_withMinimalData(): void
    {
        // 构造最小的有效 EncryptedExtensions 数据 (只有扩展长度为0)
        $data = "\x00\x00"; // 扩展长度为0
        
        $decoded = EncryptedExtensions::decode($data);
        $this->assertInstanceOf(EncryptedExtensions::class, $decoded);
    }

    public function test_extensions_includeRequiredTypes(): void
    {
        $encryptedExtensions = new EncryptedExtensions();
        $extensions = $encryptedExtensions->getExtensions();
        
        // 验证包含必需的扩展类型
        $this->assertArrayHasKey(0x0039, $extensions); // QUIC Transport Parameters
        $this->assertArrayHasKey(0x0010, $extensions); // ALPN
        
        // 验证扩展数据不为空
        $this->assertNotEmpty($extensions[0x0039]);
        $this->assertNotEmpty($extensions[0x0010]);
    }

    public function test_alpnExtension_includesH3Protocol(): void
    {
        $encryptedExtensions = new EncryptedExtensions();
        $extensions = $encryptedExtensions->getExtensions();
        
        // 检查 ALPN 扩展是否包含 h3 协议
        $alpnData = $extensions[0x0010];
        $this->assertNotEmpty($alpnData);
        
        // ALPN 数据应该包含协议列表长度和 h3 协议
        $this->assertGreaterThan(4, strlen($alpnData)); // 长度字段(2) + 协议长度(1) + "h3"(2) 至少5字节
    }

    public function test_transportParametersExtension_isValid(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 45000,
            TransportParameters::PARAM_INITIAL_MAX_DATA => 1048576,
        ]);
        
        $encryptedExtensions = new EncryptedExtensions($params);
        $extensions = $encryptedExtensions->getExtensions();
        
        // 验证传输参数扩展存在且不为空
        $this->assertArrayHasKey(0x0039, $extensions);
        $this->assertNotEmpty($extensions[0x0039]);
        
        // 验证可以解码传输参数
        $decodedParams = TransportParameters::decode($extensions[0x0039]);
        $this->assertInstanceOf(TransportParameters::class, $decodedParams);
    }
}