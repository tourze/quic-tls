<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Exception\InvalidParameterException;

class InvalidParameterExceptionTest extends TestCase
{
    public function test_inheritance(): void
    {
        $exception = new InvalidParameterException();
        $this->assertInstanceOf(\InvalidArgumentException::class, $exception);
    }

    public function test_constructor_withMessage(): void
    {
        $message = '无效参数';
        $exception = new InvalidParameterException($message);
        $this->assertEquals($message, $exception->getMessage());
    }

    public function test_constructor_withMessageAndCode(): void
    {
        $message = '无效参数';
        $code = 1004;
        $exception = new InvalidParameterException($message, $code);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
    }

    public function test_constructor_withMessageCodeAndPrevious(): void
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