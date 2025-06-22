<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\TransportParameters;

class TransportParametersTest extends TestCase
{
    public function testDefaultValues(): void
    {
        $params = new TransportParameters();
        
        // 测试默认值
        $this->assertEquals(30000, $params->getMaxIdleTimeout());
        $this->assertEquals(1472, $params->getMaxUdpPayloadSize());
        $this->assertEquals(1048576, $params->getInitialMaxData());
        $this->assertEquals(65536, $params->getInitialMaxStreamDataBidiLocal());
        $this->assertEquals(65536, $params->getInitialMaxStreamDataBidiRemote());
        $this->assertEquals(100, $params->getInitialMaxStreamsBidi());
        $this->assertEquals(100, $params->getInitialMaxStreamsUni());
    }
    
    public function testParameterSetting(): void
    {
        $params = new TransportParameters();
        
        $params->setMaxIdleTimeout(30000);
        $params->setMaxUdpPayloadSize(1200);
        $params->setInitialMaxData(1048576);
        $params->setInitialMaxStreamDataBidiLocal(262144);
        $params->setInitialMaxStreamDataBidiRemote(262144);
        $params->setInitialMaxStreamsBidi(100);
        $params->setInitialMaxStreamsUni(100);
        
        $this->assertEquals(30000, $params->getMaxIdleTimeout());
        $this->assertEquals(1200, $params->getMaxUdpPayloadSize());
        $this->assertEquals(1048576, $params->getInitialMaxData());
        $this->assertEquals(262144, $params->getInitialMaxStreamDataBidiLocal());
        $this->assertEquals(262144, $params->getInitialMaxStreamDataBidiRemote());
        $this->assertEquals(100, $params->getInitialMaxStreamsBidi());
        $this->assertEquals(100, $params->getInitialMaxStreamsUni());
    }
    
    public function testEncodeDecodeRoundtrip(): void
    {
        $params = new TransportParameters();
        $params->setMaxIdleTimeout(30000);
        $params->setMaxUdpPayloadSize(1200);
        $params->setInitialMaxData(1048576);
        $params->setInitialMaxStreamsBidi(100);
        
        $encoded = $params->encode();
        $this->assertNotEmpty($encoded);
        
        $decoded = TransportParameters::decode($encoded);
        
        $this->assertEquals($params->getMaxIdleTimeout(), $decoded->getMaxIdleTimeout());
        $this->assertEquals($params->getMaxUdpPayloadSize(), $decoded->getMaxUdpPayloadSize());
        $this->assertEquals($params->getInitialMaxData(), $decoded->getInitialMaxData());
        $this->assertEquals($params->getInitialMaxStreamsBidi(), $decoded->getInitialMaxStreamsBidi());
    }
    
    public function testNegotiation(): void
    {
        $clientParams = new TransportParameters();
        $clientParams->setMaxIdleTimeout(60000);
        $clientParams->setMaxUdpPayloadSize(1500);
        $clientParams->setInitialMaxData(2097152);
        
        $serverParams = new TransportParameters();
        $serverParams->setMaxIdleTimeout(30000);
        $serverParams->setMaxUdpPayloadSize(1200);
        $serverParams->setInitialMaxData(1048576);
        
        $negotiated = $clientParams->negotiate($serverParams);
        
        // 协商应该选择较小的值
        $this->assertEquals(30000, $negotiated->getMaxIdleTimeout());
        $this->assertEquals(1200, $negotiated->getMaxUdpPayloadSize());
        $this->assertEquals(1048576, $negotiated->getInitialMaxData());
    }
    
    public function testVarIntEncoding(): void
    {
        $params = new TransportParameters();
        
        // 测试各种大小的 VarInt
        $testValues = [0, 63, 64, 16383, 16384, 1073741823, 1073741824];
        
        foreach ($testValues as $value) {
            $params->setMaxIdleTimeout($value);
            $encoded = $params->encode();
            $decoded = TransportParameters::decode($encoded);
            $this->assertEquals($value, $decoded->getMaxIdleTimeout());
        }
    }
    
    public function testInvalidVarIntDecoding(): void
    {
        // 测试无效的 VarInt 解码
        $this->expectException(\InvalidArgumentException::class);
        
        // 创建一个无效的编码数据
        $invalidData = "\xFF\xFF\xFF\xFF\xFF"; // 无效的 VarInt
        TransportParameters::decode($invalidData);
    }
    
    public function testParameterValidation(): void
    {
        $params = new TransportParameters();
        
        // 测试边界值
        $params->setMaxUdpPayloadSize(1200);
        $this->assertEquals(1200, $params->getMaxUdpPayloadSize());
        
        // 测试最小值约束
        $params->setMaxUdpPayloadSize(100); // 应该被调整为最小值
        $this->assertGreaterThanOrEqual(1200, $params->getMaxUdpPayloadSize());
    }
    
    public function testToArray(): void
    {
        $params = new TransportParameters();
        $params->setMaxIdleTimeout(30000);
        $params->setMaxUdpPayloadSize(1200);
        
        $array = $params->toArray();
        
        $this->assertArrayHasKey(TransportParameters::PARAM_MAX_IDLE_TIMEOUT, $array);
        $this->assertArrayHasKey(TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE, $array);
        $this->assertEquals(30000, $array[TransportParameters::PARAM_MAX_IDLE_TIMEOUT]);
        $this->assertEquals(1200, $array[TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE]);
    }
    
    public function testFromArray(): void
    {
        $data = [
            'max_idle_timeout' => 30000,
            'max_udp_payload_size' => 1200,
            'initial_max_data' => 1048576,
            'initial_max_streams_bidi' => 100,
        ];
        
        $params = TransportParameters::fromArray($data);
        
        $this->assertEquals(30000, $params->getMaxIdleTimeout());
        $this->assertEquals(1200, $params->getMaxUdpPayloadSize());
        $this->assertEquals(1048576, $params->getInitialMaxData());
        $this->assertEquals(100, $params->getInitialMaxStreamsBidi());
    }
    
    public function testParameterConstants(): void
    {
        // 验证参数常量定义
        $this->assertEquals(0x0001, TransportParameters::PARAM_MAX_IDLE_TIMEOUT);
        $this->assertEquals(0x0003, TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE);
        $this->assertEquals(0x0004, TransportParameters::PARAM_INITIAL_MAX_DATA);
        $this->assertEquals(0x0005, TransportParameters::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
        $this->assertEquals(0x0006, TransportParameters::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
        $this->assertEquals(0x0008, TransportParameters::PARAM_INITIAL_MAX_STREAMS_BIDI);
        $this->assertEquals(0x0009, TransportParameters::PARAM_INITIAL_MAX_STREAMS_UNI);
    }
    
    public function testEmptyEncoding(): void
    {
        $params = new TransportParameters();
        $encoded = $params->encode();
        
        // 空参数应该生成有效的编码
        $this->assertNotEmpty($encoded);
        
        $decoded = TransportParameters::decode($encoded);
        $this->assertInstanceOf(TransportParameters::class, $decoded);
    }
    
    public function testLargeValues(): void
    {
        $params = new TransportParameters();
        
        // 测试大值
        $largeValue = 0x3FFFFFFF; // 最大的 4 字节 VarInt
        $params->setInitialMaxData($largeValue);
        
        $encoded = $params->encode();
        $decoded = TransportParameters::decode($encoded);
        
        $this->assertEquals($largeValue, $decoded->getInitialMaxData());
    }
    
    public function testUnknownParameters(): void
    {
        // 创建包含未知参数的编码数据
        $knownParams = new TransportParameters();
        $knownParams->setMaxIdleTimeout(30000);
        $encoded = $knownParams->encode();
        
        // 添加一个未知参数（高参数 ID）
        $unknownParamId = 0x8000; // 未知参数
        $unknownParamValue = "test";
        $unknownParam = $this->encodeVarInt($unknownParamId) . 
                       $this->encodeVarInt(strlen($unknownParamValue)) . 
                       $unknownParamValue;
        
        $encodedWithUnknown = $encoded . $unknownParam;
        
        // 解码应该忽略未知参数
        $decoded = TransportParameters::decode($encodedWithUnknown);
        $this->assertEquals(30000, $decoded->getMaxIdleTimeout());
    }
    
    /**
     * 辅助方法：编码 VarInt
     */
    private function encodeVarInt(int $value): string
    {
        if ($value < 64) {
            return chr($value);
        } elseif ($value < 16384) {
            return pack('n', $value | 0x4000);
        } elseif ($value < 1073741824) {
            return pack('N', $value | 0x80000000);
        } else {
            return pack('J', $value | 0xC000000000000000);
        }
    }
}