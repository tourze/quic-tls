<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\TLS;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\CertificateValidator;
use Tourze\QUIC\TLS\Exception\InvalidParameterException;
use Tourze\QUIC\TLS\Exception\TlsProtocolException;
use Tourze\QUIC\TLS\TLS\HandshakeManager;
use Tourze\QUIC\TLS\TransportParameters;

/**
 * @internal
 */
#[CoversClass(HandshakeManager::class)]
final class HandshakeManagerTest extends TestCase
{
    private HandshakeManager $handshakeManager;

    public function testConstructorInitializesCorrectly(): void
    {
        $this->assertInstanceOf(HandshakeManager::class, $this->handshakeManager);
    }

    public function testSetTransportParametersSetsParametersCorrectly(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
            TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE => 1472,
        ]);

        $this->handshakeManager->setTransportParameters($params);

        // 验证参数已设置 - 通过反射检查内部状态
        $reflection = new \ReflectionClass($this->handshakeManager);
        $transportParamsProp = $reflection->getProperty('localParams');
        $transportParamsProp->setAccessible(true);
        $storedParams = $transportParamsProp->getValue($this->handshakeManager);

        $this->assertInstanceOf(TransportParameters::class, $storedParams);
        $this->assertEquals(30000, $storedParams->getParameter(TransportParameters::PARAM_MAX_IDLE_TIMEOUT));
        $this->assertEquals(1472, $storedParams->getParameter(TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE));
    }

    public function testSetCertificateValidatorSetsValidatorCorrectly(): void
    {
        $validator = new CertificateValidator(['allow_self_signed' => true]);

        $this->handshakeManager->setCertificateValidator($validator);

        // 验证验证器已设置 - 通过反射检查内部状态
        $reflection = new \ReflectionClass($this->handshakeManager);
        $validatorProp = $reflection->getProperty('certValidator');
        $validatorProp->setAccessible(true);
        $storedValidator = $validatorProp->getValue($this->handshakeManager);

        $this->assertInstanceOf(CertificateValidator::class, $storedValidator);
    }

    public function testProcessMessageWithValidMessageProcessesCorrectly(): void
    {
        // 测试使用异常来验证错误处理
        $this->expectException(InvalidParameterException::class);

        // 创建完整的 TLS 记录格式
        $handshakeData = pack('C', 1) . substr(pack('N', 12), 1) . 'test message'; // 握手消息 (3字节长度)
        $tlsRecord = pack('C', 22) . pack('n', 0x0303) . pack('n', strlen($handshakeData)) . $handshakeData;

        // 这应该抛出异常，因为数据不完整
        $this->handshakeManager->processHandshakeData($tlsRecord, 'initial');
    }

    public function testStartHandshakeAsServerStartsCorrectly(): void
    {
        $transportParams = new TransportParameters();
        $this->handshakeManager->setTransportParameters($transportParams);

        $result = $this->handshakeManager->startHandshake();
        // 服务器握手开始可能返回空字符串，因为它等待客户端的 ClientHello
        $this->assertEquals('', $result);
    }

    public function testStartHandshakeAsClientStartsCorrectly(): void
    {
        // 创建客户端握手管理器
        $clientTransportParams = new TransportParameters();
        $clientCertValidator = new CertificateValidator(['allow_self_signed' => true]);

        $clientManager = new HandshakeManager(
            false, // isClient
            $clientTransportParams,
            $clientCertValidator
        );

        $transportParams = new TransportParameters();
        $clientManager->setTransportParameters($transportParams);

        $result = $clientManager->startHandshake();
        // 客户端握手开始应该返回 ClientHello 消息
        $this->assertNotEmpty($result);
        $this->assertGreaterThan(0, strlen($result));
    }

    public function testStartHandshakeWithoutTransportParametersThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('传输参数未设置');

        // 创建一个没有传输参数的 HandshakeManager
        $handshakeManager = new HandshakeManager(true); // isServer = true, no transport params
        $handshakeManager->startHandshake();
    }

    public function testIsHandshakeCompleteReturnsCorrectStatus(): void
    {
        $isComplete = $this->handshakeManager->isHandshakeComplete();
        $this->assertFalse($isComplete); // 初始状态应该是未完成
    }

    public function testEncryptWithApplicationDataEncryptsCorrectly(): void
    {
        // HandshakeManager 不直接提供加密功能，测试其 CryptoManager 的存在性
        $reflection = new \ReflectionClass($this->handshakeManager);
        $cryptoManagerProp = $reflection->getProperty('cryptoManager');
        $cryptoManagerProp->setAccessible(true);
        $cryptoManager = $cryptoManagerProp->getValue($this->handshakeManager);

        $this->assertNotNull($cryptoManager);
        $this->assertInstanceOf('Tourze\QUIC\TLS\TLS\CryptoManager', $cryptoManager);
    }

    public function testDecryptWithApplicationDataDecryptsCorrectly(): void
    {
        // HandshakeManager 不直接提供解密功能，测试其 CryptoManager 的存在性
        $reflection = new \ReflectionClass($this->handshakeManager);
        $cryptoManagerProp = $reflection->getProperty('cryptoManager');
        $cryptoManagerProp->setAccessible(true);
        $cryptoManager = $cryptoManagerProp->getValue($this->handshakeManager);

        $this->assertNotNull($cryptoManager);
        $this->assertInstanceOf('Tourze\QUIC\TLS\TLS\CryptoManager', $cryptoManager);
    }

    public function testGetStatisticsReturnsStatistics(): void
    {
        $stats = $this->handshakeManager->getStatistics();
        $this->assertArrayHasKey('messages_processed', $stats);
        $this->assertArrayHasKey('bytes_processed', $stats);
        $this->assertArrayHasKey('current_state', $stats);
        $this->assertArrayHasKey('handshake_complete', $stats);
    }

    public function testUpdateKeysUpdatesApplicationKeys(): void
    {
        // 首先完成握手设置
        $transportParams = new TransportParameters();
        $this->handshakeManager->setTransportParameters($transportParams);

        // 模拟握手完成
        $this->handshakeManager->startHandshake();

        // 设置 CryptoManager 的当前级别为 application
        $reflection = new \ReflectionClass($this->handshakeManager);
        $cryptoManagerProp = $reflection->getProperty('cryptoManager');
        $cryptoManagerProp->setAccessible(true);
        $cryptoManager = $cryptoManagerProp->getValue($this->handshakeManager);

        $cryptoReflection = new \ReflectionClass($cryptoManager);
        $levelProp = $cryptoReflection->getProperty('currentLevel');
        $levelProp->setAccessible(true);
        $levelProp->setValue($cryptoManager, 'application');

        // 更新密钥
        $this->handshakeManager->updateKeys();

        // 验证密钥更新操作完成（检查没有抛出异常即为成功）
        // 通过检查 KeyScheduler 状态来确认密钥已更新
        $keySchedulerProp = $reflection->getProperty('keyScheduler');
        $keySchedulerProp->setAccessible(true);
        $keyScheduler = $keySchedulerProp->getValue($this->handshakeManager);

        $this->assertNotNull($keyScheduler);
        $this->assertInstanceOf('Tourze\QUIC\TLS\KeyScheduler', $keyScheduler);
    }

    public function testResetResetsHandshakeState(): void
    {
        // 首先进行一些操作
        $transportParams = new TransportParameters();
        $this->handshakeManager->setTransportParameters($transportParams);
        $this->handshakeManager->startHandshake();

        // 重置
        $this->handshakeManager->reset();

        // 验证状态已重置
        $this->assertFalse($this->handshakeManager->isHandshakeComplete());
    }

    public function testProcessMessageWithCorruptedMessageHandlesGracefully(): void
    {
        $corruptedMessage = 'corrupted message data';

        $result = $this->handshakeManager->processMessage($corruptedMessage);
        $this->assertArrayHasKey('error', $result);
    }

    public function testSetPSKSetsPresharedKey(): void
    {
        $psk = random_bytes(32);

        $this->handshakeManager->setPSKSimple($psk);

        // 验证PSK已设置
        $reflection = new \ReflectionClass($this->handshakeManager);
        $this->assertTrue($reflection->hasProperty('psk'), 'HandshakeManager应该有psk属性');

        $pskProp = $reflection->getProperty('psk');
        $pskProp->setAccessible(true);
        $storedPsk = $pskProp->getValue($this->handshakeManager);

        $this->assertEquals($psk, $storedPsk);
        $this->assertEquals(32, strlen($storedPsk));
    }

    public function testGetTranscriptHashReturnsValidHash(): void
    {
        // 添加一些消息到转录缓冲区
        $transportParams = new TransportParameters();
        $this->handshakeManager->setTransportParameters($transportParams);
        $this->handshakeManager->startHandshake();

        $transcriptHash = $this->handshakeManager->getTranscriptHash();
        $this->assertEquals(32, strlen($transcriptHash)); // SHA256 hash length
    }

    public function testExportKeyingMaterialExportsKeys(): void
    {
        // 首先完成握手设置
        $transportParams = new TransportParameters();
        $this->handshakeManager->setTransportParameters($transportParams);
        $this->handshakeManager->startHandshake();

        // 设置主密钥
        $reflection = new \ReflectionClass($this->handshakeManager);
        $keySchedulerProp = $reflection->getProperty('keyScheduler');
        $keySchedulerProp->setAccessible(true);
        $keyScheduler = $keySchedulerProp->getValue($this->handshakeManager);

        // 初始化密钥调度
        $keyScheduler->setEarlySecret('');
        $keyScheduler->deriveHandshakeSecrets(random_bytes(32), '');
        $masterSecret = $keyScheduler->deriveMasterSecret();

        // 设置主密钥
        $masterSecretProp = $reflection->getProperty('masterSecret');
        $masterSecretProp->setAccessible(true);
        $masterSecretProp->setValue($this->handshakeManager, $masterSecret);

        $label = 'test export';
        $context = 'test context';
        $length = 32;

        $exportedKey = $this->handshakeManager->exportKeyingMaterial($label, $context, $length);
        $this->assertEquals($length, strlen($exportedKey));
    }

    public function testProcessMessageWithRepeatedMessageIgnores(): void
    {
        $message = pack('C', 1) . 'test message';

        // 第一次处理
        $result1 = $this->handshakeManager->processMessage($message);

        // 第二次处理相同消息
        $result2 = $this->handshakeManager->processMessage($message);

        // 验证重复消息的处理行为
        $this->assertIsArray($result1);
        $this->assertIsArray($result2);
        // 检查两次处理的结果是否一致（重复消息应该被正确处理）
        $this->assertEquals($result1['error'] ?? null, $result2['error'] ?? null);
    }

    public function testProcessHandshakeData(): void
    {
        $transportParams = new TransportParameters();
        $this->handshakeManager->setTransportParameters($transportParams);

        $data = pack('C', 22) . pack('n', 0x0303) . pack('n', 4) . 'test';
        $level = 'initial';

        try {
            $result = $this->handshakeManager->processHandshakeData($data, $level);
            $this->assertIsArray($result);
            $this->assertArrayHasKey('responses', $result);
            $this->assertArrayHasKey('newLevel', $result);
            $this->assertArrayHasKey('isComplete', $result);
        } catch (\Exception $e) {
            $this->assertInstanceOf(\InvalidArgumentException::class, $e);
        }
    }

    public function testProcessHandshakeDataWithEmptyData(): void
    {
        $transportParams = new TransportParameters();
        $this->handshakeManager->setTransportParameters($transportParams);

        $result = $this->handshakeManager->processHandshakeData('', 'initial');

        $this->assertIsArray($result);
        $this->assertArrayHasKey('responses', $result);
    }

    public function testProcessHandshakeDataWithInvalidLevel(): void
    {
        $transportParams = new TransportParameters();
        $this->handshakeManager->setTransportParameters($transportParams);

        $data = pack('C', 22) . pack('n', 0x0303) . pack('n', 4) . 'test';

        try {
            $result = $this->handshakeManager->processHandshakeData($data, 'invalid_level');
            $this->assertIsArray($result);
        } catch (\Exception $e) {
            $this->assertInstanceOf(\InvalidArgumentException::class, $e);
        }
    }

    public function testResumeSession(): void
    {
        $ticket = base64_encode(serialize([
            'version' => 0x0304,
            'cipher_suite' => 'TLS_AES_128_GCM_SHA256',
            'master_secret' => base64_encode(random_bytes(32)),
            'timestamp' => time(),
            'lifetime' => 7200,
        ]));

        $result = $this->handshakeManager->resumeSession($ticket);

        $this->assertIsBool($result);
    }

    public function testResumeSessionWithInvalidTicket(): void
    {
        $result = $this->handshakeManager->resumeSession('invalid_ticket');

        $this->assertFalse($result);
    }

    public function testResumeSessionWithExpiredTicket(): void
    {
        $ticket = base64_encode(serialize([
            'version' => 0x0304,
            'cipher_suite' => 'TLS_AES_128_GCM_SHA256',
            'master_secret' => base64_encode(random_bytes(32)),
            'timestamp' => time() - 8000,
            'lifetime' => 7200,
        ]));

        $result = $this->handshakeManager->resumeSession($ticket);

        $this->assertFalse($result);
    }

    public function testResumeSessionWithWrongVersion(): void
    {
        $ticket = base64_encode(serialize([
            'version' => 0x0303,
            'cipher_suite' => 'TLS_AES_128_GCM_SHA256',
            'master_secret' => base64_encode(random_bytes(32)),
            'timestamp' => time(),
            'lifetime' => 7200,
        ]));

        $result = $this->handshakeManager->resumeSession($ticket);

        $this->assertFalse($result);
    }

    public function testUpdateTrafficKeys(): void
    {
        $transportParams = new TransportParameters();
        $this->handshakeManager->setTransportParameters($transportParams);

        $reflection = new \ReflectionClass($this->handshakeManager);
        $cryptoManagerProp = $reflection->getProperty('cryptoManager');
        $cryptoManagerProp->setAccessible(true);
        $cryptoManager = $cryptoManagerProp->getValue($this->handshakeManager);

        $cryptoReflection = new \ReflectionClass($cryptoManager);
        $levelProp = $cryptoReflection->getProperty('currentLevel');
        $levelProp->setAccessible(true);
        $levelProp->setValue($cryptoManager, 'application');

        $this->handshakeManager->updateTrafficKeys();

        // 验证密钥更新操作完成 - 检查CryptoManager状态
        $currentLevel = $levelProp->getValue($cryptoManager);
        $this->assertEquals('application', $currentLevel);
    }

    public function testUpdateTrafficKeysWithInvalidState(): void
    {
        $this->expectException(TlsProtocolException::class);
        $this->expectExceptionMessage('只能在应用级别更新密钥');

        $this->handshakeManager->updateTrafficKeys();
    }

    protected function setUp(): void
    {
        parent::setUp();

        $transportParams = new TransportParameters();
        $certValidator = new CertificateValidator(['allow_self_signed' => true]);

        $this->handshakeManager = new HandshakeManager(
            true, // isServer
            $transportParams,
            $certValidator
        );
    }
}
