<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\QUIC\TLS\Exception\CertificateValidationException;

/**
 * @internal
 */
#[CoversClass(CertificateValidationException::class)]
final class CertificateValidationExceptionTest extends AbstractExceptionTestCase
{
    public function testInheritance(): void
    {
        $exception = new CertificateValidationException();
        $this->assertInstanceOf(\RuntimeException::class, $exception);
    }

    public function testConstructorWithMessage(): void
    {
        $message = '证书验证失败';
        $exception = new CertificateValidationException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function testConstructorWithMessageAndCode(): void
    {
        $message = '证书验证失败';
        $code = 1001;
        $exception = new CertificateValidationException($message, $code);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function testConstructorWithMessageCodeAndPrevious(): void
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
