<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Message;

use Tourze\QUIC\TLS\Exception\InvalidParameterException;
use Tourze\QUIC\TLS\TransportParameters;

/**
 * TLS 1.3 EncryptedExtensions消息
 */
class EncryptedExtensions
{
    /** @var array<int, string> */
    private array $extensions = [];

    private ?TransportParameters $transportParameters = null;

    public function __construct(?TransportParameters $transportParams = null)
    {
        $this->transportParameters = $transportParams ?? new TransportParameters();
        $this->buildExtensions();
    }

    /**
     * 编码EncryptedExtensions消息
     */
    public function encode(): string
    {
        $extensionsData = $this->encodeExtensions();

        return pack('n', strlen($extensionsData)) . $extensionsData;
    }

    /**
     * 从二进制数据解码EncryptedExtensions消息
     */
    public static function decode(string $data): self
    {
        $encryptedExt = new self();

        $unpackResult = unpack('n', substr($data, 0, 2));
        if (false === $unpackResult) {
            throw new InvalidParameterException('Failed to unpack extensions length');
        }
        $extensionsLength = $unpackResult[1];
        $encryptedExt->parseExtensions(substr($data, 2, $extensionsLength));

        return $encryptedExt;
    }

    /**
     * 构建扩展
     */
    private function buildExtensions(): void
    {
        // QUIC Transport Parameters
        if (null !== $this->transportParameters) {
            $this->extensions[0x0039] = $this->transportParameters->encode();
        }

        // Server Name (if needed)
        // Application Layer Protocol Negotiation (ALPN)
        $this->extensions[0x0010] = $this->buildALPNExtension(['h3']);
    }

    /**
     * 编码扩展
     */
    private function encodeExtensions(): string
    {
        $data = '';

        foreach ($this->extensions as $type => $extensionData) {
            $data .= pack('n', $type);
            $data .= pack('n', strlen($extensionData));
            $data .= $extensionData;
        }

        return $data;
    }

    /**
     * 解析扩展
     */
    private function parseExtensions(string $data): void
    {
        $offset = 0;
        $length = strlen($data);

        while ($offset < $length) {
            $unpackResult = unpack('n', substr($data, $offset, 2));
            if (false === $unpackResult) {
                throw new InvalidParameterException('Failed to unpack extension type');
            }
            $type = $unpackResult[1];
            $offset += 2;

            $unpackResult = unpack('n', substr($data, $offset, 2));
            if (false === $unpackResult) {
                throw new InvalidParameterException('Failed to unpack extension length');
            }
            $extLength = $unpackResult[1];
            $offset += 2;

            $extData = substr($data, $offset, $extLength);
            $offset += $extLength;

            $this->extensions[$type] = $extData;

            // 解析QUIC传输参数
            if (0x0039 === $type) {
                $this->transportParameters = TransportParameters::decode($extData);
            }
        }
    }

    /**
     * 构建ALPN扩展
     */
    /**
     * @param array<string> $protocols
     */
    private function buildALPNExtension(array $protocols): string
    {
        $data = '';
        $protocolsData = '';

        foreach ($protocols as $protocol) {
            $protocolsData .= chr(strlen($protocol)) . $protocol;
        }

        $data .= pack('n', strlen($protocolsData));
        $data .= $protocolsData;

        return $data;
    }

    /**
     * 获取传输参数
     */
    public function getTransportParameters(): ?TransportParameters
    {
        return $this->transportParameters;
    }

    /**
     * 设置传输参数
     */
    public function setTransportParameters(TransportParameters $params): void
    {
        $this->transportParameters = $params;
        $this->extensions[0x0039] = $params->encode();
    }

    /**
     * 获取扩展
     */
    /**
     * @return array<int, string>
     */
    public function getExtensions(): array
    {
        return $this->extensions;
    }
}
