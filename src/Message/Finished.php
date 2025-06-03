<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Message;

/**
 * TLS 1.3 Finished消息
 */
class Finished
{
    private string $verifyData;

    public function __construct(string $verifyData = '')
    {
        $this->verifyData = $verifyData;
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

    /**
     * 设置验证数据
     */
    public function setVerifyData(string $verifyData): void
    {
        $this->verifyData = $verifyData;
    }
} 