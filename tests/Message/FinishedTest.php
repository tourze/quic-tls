<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Message\Finished;

/**
 * @internal
 */
#[CoversClass(Finished::class)]
final class FinishedTest extends TestCase
{
    public function testConstructorWithoutVerifyData(): void
    {
        $finished = new Finished();
        $this->assertInstanceOf(Finished::class, $finished);
        $this->assertEquals('', $finished->getVerifyData());
    }

    public function testConstructorWithVerifyData(): void
    {
        $verifyData = 'test-verify-data';
        $finished = new Finished($verifyData);
        $this->assertEquals($verifyData, $finished->getVerifyData());
    }

    public function testEncodeWithEmptyVerifyData(): void
    {
        $finished = new Finished();
        $encoded = $finished->encode();
        $this->assertEquals('', $encoded);
    }

    public function testEncodeWithVerifyData(): void
    {
        $verifyData = 'test-verify-data';
        $finished = new Finished($verifyData);
        $encoded = $finished->encode();
        $this->assertEquals($verifyData, $encoded);
    }

    public function testEncodeAndDecodeRoundTrip(): void
    {
        $originalVerifyData = 'original-verify-data';
        $finished = new Finished($originalVerifyData);

        $encoded = $finished->encode();
        $decoded = Finished::decode($encoded);

        $this->assertEquals($originalVerifyData, $decoded->getVerifyData());
    }

    public function testDecodeWithBinaryData(): void
    {
        $binaryData = random_bytes(32); // 32字节随机数据
        $decoded = Finished::decode($binaryData);

        $this->assertEquals($binaryData, $decoded->getVerifyData());
    }

    public function testDecodeWithEmptyData(): void
    {
        $decoded = Finished::decode('');
        $this->assertEquals('', $decoded->getVerifyData());
    }

    public function testVerifyDataCanBeArbitraryLength(): void
    {
        $testCases = [
            '',
            'short',
            str_repeat('a', 32), // 32字节
            str_repeat('b', 64), // 64字节
            random_bytes(48),    // 48字节随机数据
        ];

        foreach ($testCases as $verifyData) {
            $finished = new Finished($verifyData);
            $this->assertEquals($verifyData, $finished->getVerifyData());

            // 测试编码/解码
            $encoded = $finished->encode();
            $decoded = Finished::decode($encoded);
            $this->assertEquals($verifyData, $decoded->getVerifyData());
        }
    }

    public function testVerifyDataPreservesBinaryData(): void
    {
        // 测试包含各种字节值的二进制数据
        $binaryData = '';
        for ($i = 0; $i < 256; ++$i) {
            $binaryData .= chr($i);
        }

        $finished = new Finished($binaryData);
        $this->assertEquals($binaryData, $finished->getVerifyData());

        $encoded = $finished->encode();
        $decoded = Finished::decode($encoded);
        $this->assertEquals($binaryData, $decoded->getVerifyData());
    }
}
