<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Exception\InvalidCertificateException;

class InvalidCertificateExceptionTest extends TestCase
{
    public function test_inheritance(): void
    {
        $exception = new InvalidCertificateException();
        $this->assertInstanceOf(\InvalidArgumentException::class, $exception);
    }

    public function test_constructor_withMessage(): void
    {
        $message = '无效证书';
        $exception = new InvalidCertificateException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function test_constructor_withMessageAndCode(): void
    {
        $message = '无效证书';
        $code = 1002;
        $exception = new InvalidCertificateException($message, $code);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function test_constructor_withMessageCodeAndPrevious(): void
    {
        $previous = new \Exception('原始异常');
        $message = '无效证书';
        $code = 1002;
        $exception = new InvalidCertificateException($message, $code, $previous);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}