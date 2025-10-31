<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\QUIC\TLS\Exception\InvalidCertificateException;

/**
 * @internal
 */
#[CoversClass(InvalidCertificateException::class)]
final class InvalidCertificateExceptionTest extends AbstractExceptionTestCase
{
    public function testInheritance(): void
    {
        $exception = new InvalidCertificateException();
        $this->assertInstanceOf(\InvalidArgumentException::class, $exception);
    }

    public function testConstructorWithMessage(): void
    {
        $message = '无效证书';
        $exception = new InvalidCertificateException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function testConstructorWithMessageAndCode(): void
    {
        $message = '无效证书';
        $code = 1002;
        $exception = new InvalidCertificateException($message, $code);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function testConstructorWithMessageCodeAndPrevious(): void
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
