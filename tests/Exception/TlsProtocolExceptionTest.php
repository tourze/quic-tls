<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\QUIC\TLS\Exception\TlsProtocolException;

/**
 * @internal
 */
#[CoversClass(TlsProtocolException::class)]
final class TlsProtocolExceptionTest extends AbstractExceptionTestCase
{
    public function testInheritance(): void
    {
        $exception = new TlsProtocolException();
        $this->assertInstanceOf(\RuntimeException::class, $exception);
    }

    public function testConstructorWithMessage(): void
    {
        $message = 'TLS协议错误';
        $exception = new TlsProtocolException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function testConstructorWithMessageAndCode(): void
    {
        $message = 'TLS协议错误';
        $code = 1005;
        $exception = new TlsProtocolException($message, $code);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function testConstructorWithMessageCodeAndPrevious(): void
    {
        $previous = new \Exception('原始异常');
        $message = 'TLS协议错误';
        $code = 1005;
        $exception = new TlsProtocolException($message, $code, $previous);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
