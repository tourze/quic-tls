# QUIC TLS 库

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/quic-tls.svg?style=flat-square)](https://packagist.org/packages/tourze/quic-tls)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-8892BF.svg?style=flat-square)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Code Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen.svg?style=flat-square)](#)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/quic-tls.svg?style=flat-square)](https://packagist.org/packages/tourze/quic-tls)

QUIC 协议的 TLS 1.3 握手 PHP 实现，为 QUIC 连接提供安全的加密通信层。

## 目录

- [特性](#特性)
- [依赖](#依赖)
- [安装](#安装)
- [快速开始](#快速开始)
  - [1. 基础证书验证](#1-基础证书验证)
  - [2. 简单的 TLS 握手](#2-简单的-tls-握手)
  - [3. 基础传输参数](#3-基础传输参数)
- [基本用法](#基本用法)
  - [证书验证](#证书验证)
  - [TLS 握手](#tls-握手)
  - [传输参数](#传输参数)
- [高级用法](#高级用法)
  - [自定义证书验证](#自定义证书验证)
  - [消息处理](#消息处理)
- [配置](#配置)
  - [证书验证器选项](#证书验证器选项)
  - [传输参数配置](#传输参数配置)
- [错误处理](#错误处理)
- [测试](#测试)
- [参考文档](#参考文档)
- [许可证](#许可证)

## 特性

- 🔒 完整的 TLS 1.3 握手实现
- 📜 X.509 证书验证和认证
- 🌐 支持通配符的主机名验证
- 🔑 证书链验证
- ⚙️ 传输参数协商
- 🛡️ 全面的错误处理
- 🧪 模块化验证器架构
- ✅ 广泛的测试覆盖

## 依赖

- PHP 8.1 或更高版本
- ext-openssl: OpenSSL 扩展
- tourze/quic-core: QUIC 核心协议实现
- tourze/quic-crypto: QUIC 加密功能

## 安装

```bash
composer require tourze/quic-tls
```

## 快速开始

几分钟内快速上手 QUIC TLS：

### 1. 基础证书验证

```php
<?php
require_once 'vendor/autoload.php';

use Tourze\QUIC\TLS\CertificateValidator;

// 使用默认设置创建验证器
$validator = new CertificateValidator();

// 验证证书（假设您有证书数据）
try {
    $isValid = $validator->validateCertificate([$certificateData]);
    echo $isValid ? "证书有效" : "证书无效";
} catch (Exception $e) {
    echo "验证错误: " . $e->getMessage();
}
```

### 2. 简单的 TLS 握手

```php
<?php
use Tourze\QUIC\TLS\HandshakeStateMachine;

// 创建客户端握手
$handshake = new HandshakeStateMachine(false); // false = 客户端模式

// 开始握手
$clientHello = $handshake->startClientHandshake();

// 将 clientHello 发送到服务器并获取 serverHello 响应
// $serverResponse = sendToServer($clientHello);
// $result = $handshake->processMessage($serverResponse);
```

### 3. 基础传输参数

```php
<?php
use Tourze\QUIC\TLS\TransportParameters;

// 使用常用设置创建传输参数
$params = new TransportParameters([
    TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,      // 30 秒
    TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE => 1200,   // 1.2KB
    TransportParameters::PARAM_INITIAL_MAX_DATA => 1048576,    // 1MB
]);

// 编码以便传输
$encoded = $params->encode();
```

就是这样！您现在已经准备好使用 QUIC TLS 了。更详细的示例请参见下面的章节。

## 基本用法

### 证书验证

```php
use Tourze\QUIC\TLS\CertificateValidator;

// 创建带有自定义选项的验证器
$validator = new CertificateValidator([
    'verify_peer' => true,
    'verify_peer_name' => true,
    'allow_self_signed' => false,
    'verify_depth' => 7
]);

// 验证证书链
$certificates = [$leafCert, $intermediateCert, $rootCert];
$isValid = $validator->validateCertificate($certificates);

// 带主机名验证
$isValid = $validator->validateCertificateChain($certificates, 'example.com');
```

### TLS 握手

```php
use Tourze\QUIC\TLS\HandshakeStateMachine;

// 初始化握手状态机
$handshake = new HandshakeStateMachine(false); // false 表示客户端

// 开始客户端握手
$clientHello = $handshake->startClientHandshake();

// 处理服务器消息
$response = $handshake->processMessage($serverMessage);
```

### 传输参数

```php
use Tourze\QUIC\TLS\TransportParameters;

// 创建传输参数
$localParams = new TransportParameters([
    TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
    TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE => 1200,
    TransportParameters::PARAM_INITIAL_MAX_DATA => 1048576
]);

// 与对等方参数协商
$peerParams = TransportParameters::decode($peerData);
$negotiated = $localParams->negotiate($peerParams);
```

## 高级用法

### 自定义证书验证

```php
use Tourze\QUIC\TLS\Validator\CertificateChainValidator;
use Tourze\QUIC\TLS\Validator\HostnameValidator;
use Tourze\QUIC\TLS\Validator\CALoader;

// 自定义 CA 加载
$caLoader = new CALoader();
$caLoader->addTrustedCA($customCACert);
$caLoader->loadSystemCAs();

// 自定义链验证
$chainValidator = new CertificateChainValidator(
    $caLoader->getTrustedCAs(),
    true, // 允许自签名
    10    // 最大深度
);

// 自定义主机名验证
$hostnameValidator = new HostnameValidator(true);
$isValidHostname = $hostnameValidator->validateHostname($cert, 'example.com');
```

### 消息处理

```php
use Tourze\QUIC\TLS\Message\ClientHello;
use Tourze\QUIC\TLS\Message\ServerHello;

// 解码消息
$clientHello = ClientHello::decode($binaryData);
$serverHello = ServerHello::decode($binaryData);

// 访问消息属性
$cipherSuites = $clientHello->getCipherSuites();
$extensions = $serverHello->getExtensions();
```

## 配置

### 证书验证器选项

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `verify_peer` | bool | `true` | 启用对等方证书验证 |
| `verify_peer_name` | bool | `true` | 启用主机名验证 |
| `allow_self_signed` | bool | `false` | 允许自签名证书 |
| `verify_depth` | int | `7` | 证书链最大深度 |
| `ca_file` | string | auto | CA 证书文件路径 |
| `check_revocation` | bool | `false` | 启用证书吊销检查 |

### 传输参数配置

| 参数 | 描述 |
|------|------|
| `PARAM_MAX_IDLE_TIMEOUT` | 最大空闲超时时间（毫秒） |
| `PARAM_MAX_UDP_PAYLOAD_SIZE` | 最大 UDP 载荷大小 |
| `PARAM_INITIAL_MAX_DATA` | 初始最大数据限制 |
| `PARAM_INITIAL_MAX_STREAMS_BIDI` | 初始最大双向流数量 |
| `PARAM_INITIAL_MAX_STREAMS_UNI` | 初始最大单向流数量 |

## 错误处理

库为不同的错误条件提供了特定的异常类型：

```php
use Tourze\QUIC\TLS\Exception\{CertificateValidationException, InvalidCertificateException, TlsProtocolException};

try {
    $validator->validateCertificate($certificates);
} catch (CertificateValidationException $e) {
    // 证书验证失败
} catch (InvalidCertificateException $e) {
    // 无效的证书格式
} catch (TlsProtocolException $e) {
    // TLS 协议错误
}
```

## 测试

```bash
# 运行测试
vendor/bin/phpunit packages/quic-tls/tests

# 运行带覆盖率的测试
vendor/bin/phpunit packages/quic-tls/tests --coverage-html coverage

# 静态分析
vendor/bin/phpstan analyse packages/quic-tls
```

## 参考文档

- [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://tools.ietf.org/html/rfc9000)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 9001: Using TLS to Secure QUIC](https://tools.ietf.org/html/rfc9001)
- [QUIC Transport Parameters](https://www.iana.org/assignments/quic/quic.xhtml)

## 贡献指南

我们欢迎贡献！请遵循以下指导原则：

1. **问题反馈**: 使用 GitHub Issues 报告 bug 或请求新功能
2. **代码贡献**: 
    - Fork 仓库
    - 创建功能分支
    - 为你的更改编写测试
    - 确保所有测试通过
    - 提交带有清晰描述的 Pull Request
3. **代码风格**: 遵循 PSR-12 编码标准
4. **测试**: 所有代码必须有测试覆盖

### 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/your-repo/php-monorepo.git
cd php-monorepo

# 安装依赖
composer install

# 运行测试
./vendor/bin/phpunit packages/quic-tls/tests

# 运行静态分析
./vendor/bin/phpstan analyse packages/quic-tls
```

## 更新日志

### [未发布]
- 使用 PHP 8 readonly 属性提升语法优化代码
- 改进类型安全和代码组织
- 增强测试覆盖率

### [0.0.1] - 初始版本
- 完整的 TLS 1.3 握手实现
- X.509 证书验证
- 支持通配符的主机名验证
- 传输参数协商
- 全面的错误处理

## 许可证

MIT 许可证。请查看 [许可证文件](LICENSE) 了解更多信息。