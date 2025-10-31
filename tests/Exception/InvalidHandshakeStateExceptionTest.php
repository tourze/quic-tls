<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\QUIC\TLS\Exception\InvalidHandshakeStateException;

/**
 * @internal
 */
#[CoversClass(InvalidHandshakeStateException::class)]
final class InvalidHandshakeStateExceptionTest extends AbstractExceptionTestCase
{
    public function testInheritance(): void
    {
        $exception = new InvalidHandshakeStateException();
        $this->assertInstanceOf(\RuntimeException::class, $exception);
    }

    public function testConstructorWithMessage(): void
    {
        $message = '无效握手状态';
        $exception = new InvalidHandshakeStateException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function testConstructorWithMessageAndCode(): void
    {
        $message = '无效握手状态';
        $code = 1003;
        $exception = new InvalidHandshakeStateException($message, $code);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function testConstructorWithMessageCodeAndPrevious(): void
    {
        $previous = new \Exception('原始异常');
        $message = '无效握手状态';
        $code = 1003;
        $exception = new InvalidHandshakeStateException($message, $code, $previous);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
