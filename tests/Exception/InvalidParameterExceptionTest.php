<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\QUIC\TLS\Exception\InvalidParameterException;

/**
 * @internal
 */
#[CoversClass(InvalidParameterException::class)]
final class InvalidParameterExceptionTest extends AbstractExceptionTestCase
{
    public function testInheritance(): void
    {
        $exception = new InvalidParameterException();
        $this->assertInstanceOf(\InvalidArgumentException::class, $exception);
    }

    public function testConstructorWithMessage(): void
    {
        $message = '无效参数';
        $exception = new InvalidParameterException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function testConstructorWithMessageAndCode(): void
    {
        $message = '无效参数';
        $code = 1004;
        $exception = new InvalidParameterException($message, $code);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function testConstructorWithMessageCodeAndPrevious(): void
    {
        $previous = new \Exception('原始异常');
        $message = '无效参数';
        $code = 1004;
        $exception = new InvalidParameterException($message, $code, $previous);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}
