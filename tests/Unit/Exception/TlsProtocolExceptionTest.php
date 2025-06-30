<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Exception\TlsProtocolException;

class TlsProtocolExceptionTest extends TestCase
{
    public function test_inheritance(): void
    {
        $exception = new TlsProtocolException();
        $this->assertInstanceOf(\RuntimeException::class, $exception);
    }

    public function test_constructor_withMessage(): void
    {
        $message = 'TLS协议错误';
        $exception = new TlsProtocolException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function test_constructor_withMessageAndCode(): void
    {
        $message = 'TLS协议错误';
        $code = 1005;
        $exception = new TlsProtocolException($message, $code);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function test_constructor_withMessageCodeAndPrevious(): void
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