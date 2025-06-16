<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS;

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
    public const PARAM_ACK_DELAY_EXPONENT = 0x0a;
    public const PARAM_MAX_ACK_DELAY = 0x0b;
    public const PARAM_DISABLE_ACTIVE_MIGRATION = 0x0c;
    public const PARAM_PREFERRED_ADDRESS = 0x0d;
    public const PARAM_ACTIVE_CONNECTION_ID_LIMIT = 0x0e;
    public const PARAM_INITIAL_SOURCE_CONNECTION_ID = 0x0f;
    public const PARAM_RETRY_SOURCE_CONNECTION_ID = 0x10;

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
        self::PARAM_MAX_ACK_DELAY => 25000, // 25ms
        self::PARAM_ACTIVE_CONNECTION_ID_LIMIT => 8,
    ];

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
            $id = self::decodeVarInt($data, $offset);
            $valueLength = self::decodeVarInt($data, $offset);
            
            if ($offset + $valueLength > $length) {
                throw new \InvalidArgumentException('传输参数数据不完整');
            }
            
            $valueData = substr($data, $offset, $valueLength);
            $offset += $valueLength;
            
            // 根据参数类型解析值
            if (in_array($id, [
                self::PARAM_ORIGINAL_DESTINATION_CONNECTION_ID,
                self::PARAM_STATELESS_RESET_TOKEN,
                self::PARAM_INITIAL_SOURCE_CONNECTION_ID,
                self::PARAM_RETRY_SOURCE_CONNECTION_ID,
            ])) {
                // 字节串参数
                $parameters[$id] = $valueData;
            } else {
                // 整数参数
                $valueOffset = 0;
                $parameters[$id] = self::decodeVarInt($valueData, $valueOffset);
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
        
        // 取两者的最小值作为协商结果
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
            $localValue = $this->getParameter($param);
            $peerValue = $peer->getParameter($param);
            
            if ($localValue !== null && $peerValue !== null) {
                $negotiated[$param] = min($localValue, $peerValue);
            } elseif ($localValue !== null) {
                $negotiated[$param] = $localValue;
            } elseif ($peerValue !== null) {
                $negotiated[$param] = $peerValue;
            }
        }
        
        // 复制不需要协商的参数
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
        
        return new self($negotiated);
    }

    /**
     * 设置参数
     */
    public function setParameter(int $id, $value): void
    {
        $this->parameters[$id] = $value;
    }

    /**
     * 获取参数
     */
    public function getParameter(int $id)
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
        } elseif ($value < 0x4000) {
            // 2 字节
            return pack('n', 0x4000 | $value);
        } elseif ($value < 0x40000000) {
            // 4 字节
            return pack('N', 0x80000000 | $value);
        } else {
            // 8 字节 - 使用更安全的方式处理大整数
            if ($value >= 0x4000000000000000) {
                throw new \InvalidArgumentException('值超出VarInt范围');
            }
            // 0xc000000000000000 = 13835058055282163712 (超过 PHP_INT_MAX)
            // 需要分两步处理
            $high = 0xc0000000;
            $low = $value & 0xffffffff;
            $highValue = ($value >> 32) & 0x3fffffff;
            return pack('NN', $high | $highValue, $low);
        }
    }

    /**
     * 解码可变长度整数
     */
    private static function decodeVarInt(string $data, int &$offset): int
    {
        if ($offset >= strlen($data)) {
            throw new \InvalidArgumentException('数据不足以解码VarInt');
        }
        
        $first = ord($data[$offset]);
        $length = 1 << ($first >> 6);
        
        if ($offset + $length > strlen($data)) {
            throw new \InvalidArgumentException('VarInt数据不完整');
        }
        
        $value = $first & 0x3f;
        
        for ($i = 1; $i < $length; $i++) {
            $value = ($value << 8) | ord($data[$offset + $i]);
        }
        
        $offset += $length;
        
        return $value;
    }

    /**
     * 验证传输参数的有效性
     */
    public function validate(): bool
    {
        // 检查必要参数的存在性和合理性
        $maxData = $this->getInitialMaxData();
        if ($maxData > 0xffffffff) {
            return false;
        }
        
        $maxUdpPayload = $this->getMaxUdpPayloadSize();
        if ($maxUdpPayload < 1200 || $maxUdpPayload > 65527) {
            return false;
        }
        
        $ackDelayExponent = $this->getParameter(self::PARAM_ACK_DELAY_EXPONENT);
        if ($ackDelayExponent !== null && $ackDelayExponent > 20) {
            return false;
        }
        
        $maxAckDelay = $this->getParameter(self::PARAM_MAX_ACK_DELAY);
        if ($maxAckDelay !== null && $maxAckDelay >= 16384) {
            return false;
        }
        
        return true;
    }

    /**
     * 转换为数组
     */
    public function toArray(): array
    {
        return $this->parameters;
    }
    
    /**
     * 从数组创建实例
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