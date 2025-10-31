<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS;

use Tourze\QUIC\TLS\Exception\InvalidParameterException;

/**
 * QUIC传输参数处理类
 *
 * 根据RFC 9000实现QUIC传输参数的编解码和协商
 */
class TransportParameters
{
    // 传输参数ID常量
    public const PARAM_ORIGINAL_DESTINATION_CONNECTION_ID = 0x00;
    public const PARAM_MAX_IDLE_TIMEOUT = 0x01;
    public const PARAM_STATELESS_RESET_TOKEN = 0x02;
    public const PARAM_MAX_UDP_PAYLOAD_SIZE = 0x03;
    public const PARAM_INITIAL_MAX_DATA = 0x04;
    public const PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05;
    public const PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06;
    public const PARAM_INITIAL_MAX_STREAM_DATA_UNI = 0x07;
    public const PARAM_INITIAL_MAX_STREAMS_BIDI = 0x08;
    public const PARAM_INITIAL_MAX_STREAMS_UNI = 0x09;
    public const PARAM_ACK_DELAY_EXPONENT = 0x0A;
    public const PARAM_MAX_ACK_DELAY = 0x0B;
    public const PARAM_DISABLE_ACTIVE_MIGRATION = 0x0C;
    public const PARAM_PREFERRED_ADDRESS = 0x0D;
    public const PARAM_ACTIVE_CONNECTION_ID_LIMIT = 0x0E;
    public const PARAM_INITIAL_SOURCE_CONNECTION_ID = 0x0F;
    public const PARAM_RETRY_SOURCE_CONNECTION_ID = 0x10;

    /** @var array<int, mixed> */
    private array $parameters = [];

    /**
     * 默认传输参数
     */
    private const DEFAULT_PARAMS = [
        self::PARAM_MAX_IDLE_TIMEOUT => 30000, // 30秒
        self::PARAM_MAX_UDP_PAYLOAD_SIZE => 1472, // 标准以太网MTU减去IP/UDP头
        self::PARAM_INITIAL_MAX_DATA => 1048576, // 1MB
        self::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => 65536, // 64KB
        self::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => 65536, // 64KB
        self::PARAM_INITIAL_MAX_STREAM_DATA_UNI => 65536, // 64KB
        self::PARAM_INITIAL_MAX_STREAMS_BIDI => 100,
        self::PARAM_INITIAL_MAX_STREAMS_UNI => 100,
        self::PARAM_ACK_DELAY_EXPONENT => 3,
        self::PARAM_MAX_ACK_DELAY => 25, // 25ms
        self::PARAM_ACTIVE_CONNECTION_ID_LIMIT => 8,
    ];

    /**
     * @param array<int, mixed> $parameters
     */
    public function __construct(array $parameters = [])
    {
        // 使用 + 运算符合并参数，然后覆盖提供的参数
        $this->parameters = self::DEFAULT_PARAMS;
        foreach ($parameters as $id => $value) {
            $this->parameters[$id] = $value;
        }
    }

    /**
     * 编码传输参数为二进制格式
     */
    public function encode(): string
    {
        $data = '';

        foreach ($this->parameters as $id => $value) {
            $data .= $this->encodeVarInt($id);

            if (is_string($value)) {
                // 字符串值（如连接ID）
                $data .= $this->encodeVarInt(strlen($value));
                $data .= $value;
            } else {
                // 整数值
                $encoded = $this->encodeVarInt($value);
                $data .= $this->encodeVarInt(strlen($encoded));
                $data .= $encoded;
            }
        }

        return $data;
    }

    /**
     * 从二进制数据解码传输参数
     */
    public static function decode(string $data): self
    {
        $parameters = [];
        $offset = 0;
        $length = strlen($data);

        while ($offset < $length) {
            $idResult = self::decodeVarInt($data, $offset);
            $id = $idResult['value'];
            $offset = $idResult['offset'];

            $valueLengthResult = self::decodeVarInt($data, $offset);
            $valueLength = $valueLengthResult['value'];
            $offset = $valueLengthResult['offset'];

            if ($offset + $valueLength > $length) {
                throw new InvalidParameterException('传输参数数据不完整');
            }

            $valueData = substr($data, $offset, $valueLength);
            $offset += $valueLength;

            // 根据参数类型解析值
            if (in_array($id, [
                self::PARAM_ORIGINAL_DESTINATION_CONNECTION_ID,
                self::PARAM_STATELESS_RESET_TOKEN,
                self::PARAM_INITIAL_SOURCE_CONNECTION_ID,
                self::PARAM_RETRY_SOURCE_CONNECTION_ID,
            ], true)) {
                // 字节串参数
                $parameters[$id] = $valueData;
            } else {
                // 整数参数
                $valueResult = self::decodeVarInt($valueData, 0);
                $parameters[$id] = $valueResult['value'];
            }
        }

        return new self($parameters);
    }

    /**
     * 协商传输参数
     */
    public function negotiate(self $peer): self
    {
        $negotiated = [];

        $negotiated = $this->negotiateMinimumParameters($peer, $negotiated);
        $negotiated = $this->copyCommunicationParameters($peer, $negotiated);

        return new self($negotiated);
    }

    /**
     * 协商需要取最小值的参数
     */
    /**
     * @param array<int, mixed> $negotiated
     * @return array<int, mixed>
     */
    private function negotiateMinimumParameters(self $peer, array $negotiated): array
    {
        $minParams = [
            self::PARAM_MAX_IDLE_TIMEOUT,
            self::PARAM_MAX_UDP_PAYLOAD_SIZE,
            self::PARAM_INITIAL_MAX_DATA,
            self::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self::PARAM_INITIAL_MAX_STREAM_DATA_UNI,
            self::PARAM_INITIAL_MAX_STREAMS_BIDI,
            self::PARAM_INITIAL_MAX_STREAMS_UNI,
            self::PARAM_MAX_ACK_DELAY,
            self::PARAM_ACTIVE_CONNECTION_ID_LIMIT,
        ];

        foreach ($minParams as $param) {
            $negotiated = $this->negotiateParameter($peer, $param, $negotiated);
        }

        return $negotiated;
    }

    /**
     * 协商单个参数
     */
    /**
     * @param array<int, mixed> $negotiated
     * @return array<int, mixed>
     */
    private function negotiateParameter(self $peer, int $param, array $negotiated): array
    {
        $localValue = $this->getParameter($param);
        $peerValue = $peer->getParameter($param);

        if (null !== $localValue && null !== $peerValue) {
            $negotiated[$param] = min($localValue, $peerValue);
        } elseif (null !== $localValue) {
            $negotiated[$param] = $localValue;
        } elseif (null !== $peerValue) {
            $negotiated[$param] = $peerValue;
        }

        return $negotiated;
    }

    /**
     * 复制不需要协商的参数
     */
    /**
     * @param array<int, mixed> $negotiated
     * @return array<int, mixed>
     */
    private function copyCommunicationParameters(self $peer, array $negotiated): array
    {
        $copyParams = [
            self::PARAM_ACK_DELAY_EXPONENT,
            self::PARAM_DISABLE_ACTIVE_MIGRATION,
            self::PARAM_PREFERRED_ADDRESS,
        ];

        foreach ($copyParams as $param) {
            if ($peer->hasParameter($param)) {
                $negotiated[$param] = $peer->getParameter($param);
            }
        }

        return $negotiated;
    }

    /**
     * 设置参数
     */
    public function setParameter(int $id, mixed $value): void
    {
        $this->parameters[$id] = $value;
    }

    /**
     * 获取参数
     */
    public function getParameter(int $id): mixed
    {
        return $this->parameters[$id] ?? null;
    }

    /**
     * 检查是否有特定参数
     */
    public function hasParameter(int $id): bool
    {
        return isset($this->parameters[$id]);
    }

    /**
     * 获取所有参数
     */
    /**
     * @return array<int, mixed>
     */
    public function getAllParameters(): array
    {
        return $this->parameters;
    }

    /**
     * 获取最大空闲超时
     */
    public function getMaxIdleTimeout(): int
    {
        return $this->getParameter(self::PARAM_MAX_IDLE_TIMEOUT) ?? 0;
    }

    /**
     * 获取最大UDP载荷大小
     */
    public function getMaxUdpPayloadSize(): int
    {
        return $this->getParameter(self::PARAM_MAX_UDP_PAYLOAD_SIZE) ?? 1200;
    }

    /**
     * 获取初始最大数据
     */
    public function getInitialMaxData(): int
    {
        return $this->getParameter(self::PARAM_INITIAL_MAX_DATA) ?? 0;
    }

    /**
     * 获取初始最大流数据（双向本地）
     */
    public function getInitialMaxStreamDataBidiLocal(): int
    {
        return $this->getParameter(self::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL) ?? 0;
    }

    /**
     * 获取初始最大流数据（双向远程）
     */
    public function getInitialMaxStreamDataBidiRemote(): int
    {
        return $this->getParameter(self::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE) ?? 0;
    }

    /**
     * 获取初始最大流数据（单向）
     */
    public function getInitialMaxStreamDataUni(): int
    {
        return $this->getParameter(self::PARAM_INITIAL_MAX_STREAM_DATA_UNI) ?? 0;
    }

    /**
     * 获取初始最大双向流数量
     */
    public function getInitialMaxStreamsBidi(): int
    {
        return $this->getParameter(self::PARAM_INITIAL_MAX_STREAMS_BIDI) ?? 0;
    }

    /**
     * 获取初始最大单向流数量
     */
    public function getInitialMaxStreamsUni(): int
    {
        return $this->getParameter(self::PARAM_INITIAL_MAX_STREAMS_UNI) ?? 0;
    }

    /**
     * 设置最大空闲超时
     */
    public function setMaxIdleTimeout(int $timeout): void
    {
        $this->setParameter(self::PARAM_MAX_IDLE_TIMEOUT, $timeout);
    }

    /**
     * 设置最大UDP载荷大小
     */
    public function setMaxUdpPayloadSize(int $size): void
    {
        // QUIC 规范要求最小值为 1200
        $size = max(1200, $size);
        $this->setParameter(self::PARAM_MAX_UDP_PAYLOAD_SIZE, $size);
    }

    /**
     * 设置初始最大数据
     */
    public function setInitialMaxData(int $data): void
    {
        $this->setParameter(self::PARAM_INITIAL_MAX_DATA, $data);
    }

    /**
     * 设置初始最大流数据（双向本地）
     */
    public function setInitialMaxStreamDataBidiLocal(int $data): void
    {
        $this->setParameter(self::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, $data);
    }

    /**
     * 设置初始最大流数据（双向远程）
     */
    public function setInitialMaxStreamDataBidiRemote(int $data): void
    {
        $this->setParameter(self::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, $data);
    }

    /**
     * 设置初始最大双向流数量
     */
    public function setInitialMaxStreamsBidi(int $streams): void
    {
        $this->setParameter(self::PARAM_INITIAL_MAX_STREAMS_BIDI, $streams);
    }

    /**
     * 设置初始最大单向流数量
     */
    public function setInitialMaxStreamsUni(int $streams): void
    {
        $this->setParameter(self::PARAM_INITIAL_MAX_STREAMS_UNI, $streams);
    }

    /**
     * 编码可变长度整数
     */
    private function encodeVarInt(int $value): string
    {
        if ($value < 0x40) {
            // 1 字节
            return chr($value);
        }
        if ($value < 0x4000) {
            // 2 字节
            return pack('n', 0x4000 | $value);
        }
        if ($value < 0x40000000) {
            // 4 字节
            return pack('N', 0x80000000 | $value);
        }
        // 8 字节 - 使用更安全的方式处理大整数
        if ($value >= 0x4000000000000000) {
            throw new InvalidParameterException('值超出VarInt范围');
        }
        // 0xc000000000000000 = 13835058055282163712 (超过 PHP_INT_MAX)
        // 需要分两步处理
        $high = 0xC0000000;
        $low = $value & 0xFFFFFFFF;
        $highValue = ($value >> 32) & 0x3FFFFFFF;

        return pack('NN', $high | $highValue, $low);
    }

    /**
     * 解码可变长度整数
     * @return array{value: int, offset: int}
     */
    private static function decodeVarInt(string $data, int $offset): array
    {
        if ($offset >= strlen($data)) {
            throw new InvalidParameterException('数据不足以解码VarInt');
        }

        $first = ord($data[$offset]);
        $length = 1 << ($first >> 6);

        if ($offset + $length > strlen($data)) {
            throw new InvalidParameterException('VarInt数据不完整');
        }

        $value = $first & 0x3F;

        for ($i = 1; $i < $length; ++$i) {
            $value = ($value << 8) | ord($data[$offset + $i]);
        }

        $newOffset = $offset + $length;

        return ['value' => $value, 'offset' => $newOffset];
    }

    /**
     * 验证传输参数的有效性
     */
    public function validate(): bool
    {
        // 检查必要参数的存在性和合理性
        $maxData = $this->getInitialMaxData();
        if ($maxData > 0xFFFFFFFF) {
            return false;
        }

        $maxUdpPayload = $this->getMaxUdpPayloadSize();
        if ($maxUdpPayload < 1200 || $maxUdpPayload > 65527) {
            return false;
        }

        $ackDelayExponent = $this->getParameter(self::PARAM_ACK_DELAY_EXPONENT);
        if (null !== $ackDelayExponent && $ackDelayExponent > 20) {
            return false;
        }

        $maxAckDelay = $this->getParameter(self::PARAM_MAX_ACK_DELAY);
        if (null !== $maxAckDelay && $maxAckDelay >= 16384) {
            return false;
        }

        return true;
    }

    /**
     * 转换为数组
     */
    /**
     * @return array<int, mixed>
     */
    public function toArray(): array
    {
        return $this->parameters;
    }

    /**
     * 从数组创建实例
     */
    /**
     * @param array<string|int, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $instance = new self();

        foreach ($data as $paramId => $value) {
            if (is_string($paramId)) {
                // 如果 paramId 是字符串，尝试转换为对应的常量值
                $paramId = match ($paramId) {
                    'max_idle_timeout' => self::PARAM_MAX_IDLE_TIMEOUT,
                    'max_udp_payload_size' => self::PARAM_MAX_UDP_PAYLOAD_SIZE,
                    'initial_max_data' => self::PARAM_INITIAL_MAX_DATA,
                    'initial_max_stream_data_bidi_local' => self::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                    'initial_max_stream_data_bidi_remote' => self::PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                    'initial_max_stream_data_uni' => self::PARAM_INITIAL_MAX_STREAM_DATA_UNI,
                    'initial_max_streams_bidi' => self::PARAM_INITIAL_MAX_STREAMS_BIDI,
                    'initial_max_streams_uni' => self::PARAM_INITIAL_MAX_STREAMS_UNI,
                    'ack_delay_exponent' => self::PARAM_ACK_DELAY_EXPONENT,
                    'max_ack_delay' => self::PARAM_MAX_ACK_DELAY,
                    'active_connection_id_limit' => self::PARAM_ACTIVE_CONNECTION_ID_LIMIT,
                    default => (int) $paramId,
                };
            }
            $instance->setParameter($paramId, $value);
        }

        return $instance;
    }
}
