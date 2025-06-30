<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Exception\CertificateValidationException;

class CertificateValidationExceptionTest extends TestCase
{
    public function test_inheritance(): void
    {
        $exception = new CertificateValidationException();
        $this->assertInstanceOf(\RuntimeException::class, $exception);
    }

    public function test_constructor_withMessage(): void
    {
        $message = '证书验证失败';
        $exception = new CertificateValidationException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function test_constructor_withMessageAndCode(): void
    {
        $message = '证书验证失败';
        $code = 1001;
        $exception = new CertificateValidationException($message, $code);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function test_constructor_withMessageCodeAndPrevious(): void
    {
        $previous = new \Exception('原始异常');
        $message = '证书验证失败';
        $code = 1001;
        $exception = new CertificateValidationException($message, $code, $previous);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}