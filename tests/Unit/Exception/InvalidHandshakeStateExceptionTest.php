<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Exception\InvalidHandshakeStateException;

class InvalidHandshakeStateExceptionTest extends TestCase
{
    public function test_inheritance(): void
    {
        $exception = new InvalidHandshakeStateException();
        $this->assertInstanceOf(\RuntimeException::class, $exception);
    }

    public function test_constructor_withMessage(): void
    {
        $message = '无效握手状态';
        $exception = new InvalidHandshakeStateException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function test_constructor_withMessageAndCode(): void
    {
        $message = '无效握手状态';
        $code = 1003;
        $exception = new InvalidHandshakeStateException($message, $code);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function test_constructor_withMessageCodeAndPrevious(): void
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