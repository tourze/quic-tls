<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Message;

/**
 * TLS 1.3 Finished消息
 */
class Finished
{
    public function __construct(private readonly string $verifyData = '')
    {
    }

    /**
     * 编码Finished消息
     */
    public function encode(): string
    {
        return $this->verifyData;
    }

    /**
     * 从二进制数据解码Finished消息
     */
    public static function decode(string $data): self
    {
        return new self($data);
    }

    /**
     * 获取验证数据
     */
    public function getVerifyData(): string
    {
        return $this->verifyData;
    }
}
