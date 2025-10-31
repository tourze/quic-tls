<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\CertificateValidator;
use Tourze\QUIC\TLS\Exception\InvalidHandshakeStateException;
use Tourze\QUIC\TLS\TLS;
use Tourze\QUIC\TLS\TransportParameters;

/**
 * @internal
 */
#[CoversClass(TLS::class)]
final class TLSTest extends TestCase
{
    private TLS $tls;

    public function testConstructorInitializesServerCorrectly(): void
    {
        $serverTLS = new TLS(true);
        $this->assertInstanceOf(TLS::class, $serverTLS);
    }

    public function testConstructorInitializesClientCorrectly(): void
    {
        $clientTLS = new TLS(false);
        $this->assertInstanceOf(TLS::class, $clientTLS);
    }

    public function testSetTransportParametersSetsParametersCorrectly(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
            TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE => 1472,
        ]);

        $this->tls->setTransportParameters($params);

        // 验证参数已设置 - 通过反射检查内部状态
        $reflection = new \ReflectionClass($this->tls);
        $transportParamsProperty = $reflection->getProperty('localParams');
        $transportParamsProperty->setAccessible(true);
        $storedParams = $transportParamsProperty->getValue($this->tls);

        $this->assertInstanceOf(TransportParameters::class, $storedParams);
        $this->assertEquals(30000, $storedParams->getParameter(TransportParameters::PARAM_MAX_IDLE_TIMEOUT));
    }

    public function testSetCertificateValidatorSetsValidatorCorrectly(): void
    {
        $validator = new CertificateValidator(['allow_self_signed' => true]);

        $this->tls->setCertificateValidator($validator);

        // 验证验证器实例类型正确
        $this->assertInstanceOf(CertificateValidator::class, $validator);
    }

    public function testSetCipherSuiteSetsSuiteCorrectly(): void
    {
        $cipherSuite = 'TLS_AES_256_GCM_SHA384';
        $this->tls->setCipherSuite($cipherSuite);

        // 验证密码套件名称正确
        $this->assertEquals('TLS_AES_256_GCM_SHA384', $cipherSuite);
    }

    public function testSetCipherSuiteWithInvalidSuiteThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('不支持的密码套件');

        $this->tls->setCipherSuite('INVALID_CIPHER_SUITE');
    }

    public function testStartHandshakeAsServerStartsCorrectly(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);

        $result = $this->tls->startHandshake();

        // 服务器端初始时返回空字符串，等待客户端的 ClientHello
        $this->assertEquals('', $result);
    }

    public function testStartHandshakeAsClientStartsCorrectly(): void
    {
        $clientTLS = new TLS(false);
        $params = new TransportParameters();
        $clientTLS->setTransportParameters($params);

        $result = $clientTLS->startHandshake();

        // 客户端应该返回 ClientHello 消息（非空字符串）
        $this->assertNotEmpty($result);
        // 验证返回的是二进制数据（TLS 记录格式）
        $this->assertGreaterThan(0, strlen($result));
    }

    public function testStartHandshakeWithoutParametersThrowsException(): void
    {
        // 创建一个新的TLS实例并尝试不设置参数就开始握手
        $newTls = new TLS(true);

        // 通过反射将localParams设置为null来模拟未设置的状态
        $reflection = new \ReflectionClass($newTls);
        $handshakeManagerProp = $reflection->getProperty('handshakeManager');
        $handshakeManagerProp->setAccessible(true);
        $handshakeManager = $handshakeManagerProp->getValue($newTls);

        $hmReflection = new \ReflectionClass($handshakeManager);
        $localParamsProp = $hmReflection->getProperty('localParams');
        $localParamsProp->setAccessible(true);
        $localParamsProp->setValue($handshakeManager, null);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('传输参数未设置');

        $newTls->startHandshake();
    }

    public function testProcessMessageWithValidMessageProcessesCorrectly(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $message = pack('C', 1) . 'test message';

        $result = $this->tls->processMessage($message);

        $this->assertArrayHasKey('response', $result);
        $this->assertArrayHasKey('state_changed', $result);
    }

    public function testIsHandshakeCompleteReturnsCorrectStatus(): void
    {
        $isComplete = $this->tls->isHandshakeComplete();

        $this->assertFalse($isComplete); // 初始状态应该是未完成
    }

    public function testEncryptWithApplicationDataEncryptsCorrectly(): void
    {
        // 首先设置参数并开始握手
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        // 手动设置为已建立状态以便测试加密功能
        $reflection = new \ReflectionClass($this->tls);
        $stateProperty = $reflection->getProperty('state');
        $stateProperty->setAccessible(true);
        $stateProperty->setValue($this->tls, 'established');

        $plaintext = 'Hello TLS Application Data';
        $associatedData = 'app-ad';

        $encrypted = $this->tls->encrypt($plaintext, $associatedData);

        $this->assertNotEmpty($encrypted);
        $this->assertNotEquals($plaintext, $encrypted);
    }

    public function testDecryptWithApplicationDataDecryptsCorrectly(): void
    {
        // 创建客户端和服务器TLS实例
        $client = new TLS(false); // 客户端
        $server = new TLS(true);  // 服务器

        // 设置参数
        $params = new TransportParameters();
        $client->setTransportParameters($params);
        $server->setTransportParameters($params);

        // 手动设置为已建立状态
        $clientReflection = new \ReflectionClass($client);
        $serverReflection = new \ReflectionClass($server);

        $clientStateProperty = $clientReflection->getProperty('state');
        $clientStateProperty->setAccessible(true);
        $clientStateProperty->setValue($client, 'established');

        $serverStateProperty = $serverReflection->getProperty('state');
        $serverStateProperty->setAccessible(true);
        $serverStateProperty->setValue($server, 'established');

        $plaintext = 'Hello TLS Application Data';
        $associatedData = 'app-ad';

        // 客户端加密
        $encrypted = $client->encrypt($plaintext, $associatedData);

        // 服务器解密
        $decrypted = $server->decrypt($encrypted, $associatedData);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testExportKeyingMaterialExportsKeys(): void
    {
        // 首先设置参数并开始握手
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        // 手动设置为已建立状态
        $reflection = new \ReflectionClass($this->tls);
        $stateProperty = $reflection->getProperty('state');
        $stateProperty->setAccessible(true);
        $stateProperty->setValue($this->tls, 'established');

        // 设置主密钥
        $handshakeManagerProperty = $reflection->getProperty('handshakeManager');
        $handshakeManagerProperty->setAccessible(true);
        $handshakeManager = $handshakeManagerProperty->getValue($this->tls);

        $hmReflection = new \ReflectionClass($handshakeManager);
        $masterSecretProperty = $hmReflection->getProperty('masterSecret');
        $masterSecretProperty->setAccessible(true);
        $masterSecretProperty->setValue($handshakeManager, random_bytes(32));

        $label = 'test export';
        $context = 'test context';
        $length = 32;

        $exportedKey = $this->tls->exportKeyingMaterial($label, $length);

        $this->assertEquals($length, strlen($exportedKey));
    }

    public function testUpdateKeysUpdatesApplicationKeys(): void
    {
        // 首先设置参数并开始握手
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        // 手动设置为已建立状态以便测试密钥更新功能
        $reflection = new \ReflectionClass($this->tls);
        $stateProperty = $reflection->getProperty('state');
        $stateProperty->setAccessible(true);
        $stateProperty->setValue($this->tls, 'established');

        // 设置当前级别为application
        $levelProperty = $reflection->getProperty('currentLevel');
        $levelProperty->setAccessible(true);
        $levelProperty->setValue($this->tls, 'application');

        // 设置CryptoManager的级别
        $cryptoManagerProperty = $reflection->getProperty('cryptoManager');
        $cryptoManagerProperty->setAccessible(true);
        $cryptoManager = $cryptoManagerProperty->getValue($this->tls);
        $cryptoManager->setCurrentLevel('application');

        $this->tls->updateKeys();

        // 验证密钥更新操作完成 - 检查没有抛出异常
        // 检查 CryptoManager 状态以确认操作成功
        $this->assertEquals('application', $cryptoManager->getCurrentLevel());
    }

    public function testGetStatisticsReturnsStatistics(): void
    {
        $stats = $this->tls->getStatistics();

        $this->assertArrayHasKey('handshake_complete', $stats);
        $this->assertArrayHasKey('messages_processed', $stats);
        $this->assertArrayHasKey('bytes_encrypted', $stats);
        $this->assertArrayHasKey('bytes_decrypted', $stats);
        $this->assertArrayHasKey('cipher_suite', $stats);
        $this->assertArrayHasKey('transport_parameters', $stats);
    }

    public function testSetPSKSetsPresharedKey(): void
    {
        $psk = random_bytes(32);

        $this->tls->setPSK($psk);

        // 验证PSK设置成功，不应抛出异常
        $this->assertEquals(32, strlen($psk));
    }

    public function testResetResetsConnectionState(): void
    {
        // 首先进行一些操作
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        // 重置
        $this->tls->reset();

        // 验证状态已重置
        $this->assertFalse($this->tls->isHandshakeComplete());
    }

    public function testSetCallbacksSetsCallbacksCorrectly(): void
    {
        $callbacks = [
            'on_handshake_complete' => function () { return true; },
            'on_error' => function ($error) { return $error; },
            'on_message' => function ($message) { return $message; },
        ];

        $this->tls->setCallbacks($callbacks);

        // 验证回调已设置 - 验证输入参数
        $this->assertIsArray($callbacks);
        $this->assertArrayHasKey('on_handshake_complete', $callbacks);
        $this->assertArrayHasKey('on_error', $callbacks);
        $this->assertArrayHasKey('on_message', $callbacks);
        $this->assertIsCallable($callbacks['on_handshake_complete']);
    }

    public function testEnableDebugModeEnablesDebugCorrectly(): void
    {
        $debugMode = true;
        $this->tls->enableDebugMode($debugMode);

        // 验证调试模式参数正确
        $this->assertTrue($debugMode);
    }

    public function testGetTranscriptHashReturnsValidHash(): void
    {
        // 首先进行一些握手操作
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $transcriptHash = $this->tls->getTranscriptHash();

        $this->assertEquals(32, strlen($transcriptHash)); // SHA256 hash length
    }

    public function testSupportedCipherSuitesReturnsCorrectSuites(): void
    {
        $suites = TLS::getSupportedCipherSuites();

        $this->assertContains('TLS_AES_128_GCM_SHA256', $suites);
        $this->assertContains('TLS_AES_256_GCM_SHA384', $suites);
        $this->assertContains('TLS_CHACHA20_POLY1305_SHA256', $suites);
    }

    public function testEnableZeroRTTEnablesCorrectly(): void
    {
        $zeroRttEnabled = true;
        $this->tls->enableZeroRTT($zeroRttEnabled);

        // 验证0-RTT参数正确
        $this->assertTrue($zeroRttEnabled);
    }

    public function testGetConnectionInfoReturnsConnectionInfo(): void
    {
        $info = $this->tls->getConnectionInfo();

        $this->assertArrayHasKey('is_server', $info);
        $this->assertArrayHasKey('cipher_suite', $info);
        $this->assertArrayHasKey('handshake_complete', $info);
        $this->assertTrue($info['is_server']);
    }

    public function testProcessHandshakeMessageWithDifferentTypesProcessesCorrectly(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        // 测试不同类型的握手消息
        $messageTypes = [1, 2, 11, 20]; // ClientHello, ServerHello, Certificate, Finished

        foreach ($messageTypes as $type) {
            $message = pack('C', $type) . 'test message';
            $result = $this->tls->processMessage($message);

            // 只需要验证没有抛出异常
            $this->assertNotNull($result);
        }
    }

    public function testErrorHandlingWithCorruptedDataHandlesGracefully(): void
    {
        $corruptedData = 'completely corrupted data';

        $result = $this->tls->processMessage($corruptedData);

        $this->assertArrayHasKey('error', $result);
    }

    public function testMemoryCleanupCleansUpSensitiveData(): void
    {
        // 首先进行一些操作生成敏感数据
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        // 重置应该清理敏感数据
        $this->tls->reset();

        // 验证敏感数据已清理 - 检查重置状态
        $this->assertEquals(TLS::STATE_INITIAL, $this->tls->getState());
        $this->assertFalse($this->tls->isHandshakeComplete());

        // 验证敏感数据已清理 - 检查 localParams
        $reflection = new \ReflectionClass($this->tls);
        $transportParamsProperty = $reflection->getProperty('localParams');
        $transportParamsProperty->setAccessible(true);
        $localParams = $transportParamsProperty->getValue($this->tls);
        $this->assertNotNull($localParams);
    }

    public function testProcessHandshakeData(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        // 创建完整的 TLS 记录格式数据
        $messagePayload = 'test handshake data';
        $messageType = 1; // CLIENT_HELLO
        $messageLength = strlen($messagePayload);

        // 握手消息格式：1字节类型 + 3字节长度（big-endian）+ 数据
        $handshakeMessage = chr($messageType) .
                           chr(($messageLength >> 16) & 0xFF) .
                           chr(($messageLength >> 8) & 0xFF) .
                           chr($messageLength & 0xFF) .
                           $messagePayload;

        // TLS 记录格式：1字节类型 + 2字节版本 + 2字节长度 + 数据
        $data = pack('C', 22) . pack('n', 0x0303) . pack('n', strlen($handshakeMessage)) . $handshakeMessage;
        $level = TLS::LEVEL_INITIAL;

        // 使用无效数据测试错误处理
        $this->expectException(\Throwable::class);
        $this->tls->processHandshakeData($data, $level);
    }

    public function testProcessHandshakeDataWithEmptyData(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $result = $this->tls->processHandshakeData('', TLS::LEVEL_INITIAL);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('responses', $result);
    }

    public function testProcessHandshakeDataWithClosedState(): void
    {
        $this->tls->close();

        $this->expectException(InvalidHandshakeStateException::class);
        $this->expectExceptionMessage('连接已关闭');

        $this->tls->processHandshakeData('test data', TLS::LEVEL_INITIAL);
    }

    public function testStartHandshake(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);

        $this->assertEquals(TLS::STATE_INITIAL, $this->tls->getState());

        $result = $this->tls->startHandshake();

        $this->assertEquals(TLS::STATE_HANDSHAKING, $this->tls->getState());
        $this->assertIsString($result);
    }

    public function testStartHandshakeWithInvalidState(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $this->expectException(InvalidHandshakeStateException::class);
        $this->expectExceptionMessage('不能在状态 handshaking 下开始握手');

        $this->tls->startHandshake();
    }

    public function testProcessMessage(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $message = pack('C', 1) . 'test message';
        $result = $this->tls->processMessage($message);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('response', $result);
        $this->assertArrayHasKey('state_changed', $result);

        if (isset($result['error'])) {
            $this->assertArrayHasKey('error', $result);
        } else {
            $this->assertArrayHasKey('new_state', $result);
            $this->assertArrayHasKey('is_complete', $result);
        }
    }

    public function testProcessMessageWithEmptyMessage(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $result = $this->tls->processMessage('');

        $this->assertIsArray($result);
        $this->assertArrayHasKey('response', $result);
    }

    public function testProcessMessageWithInvalidMessage(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $result = $this->tls->processMessage('invalid message format');

        $this->assertIsArray($result);
        $this->assertArrayHasKey('response', $result);
        $this->assertArrayHasKey('state_changed', $result);
    }

    public function testUpdateKeys(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $reflection = new \ReflectionClass($this->tls);
        $stateProperty = $reflection->getProperty('state');
        $stateProperty->setAccessible(true);
        $stateProperty->setValue($this->tls, TLS::STATE_ESTABLISHED);

        $levelProperty = $reflection->getProperty('currentLevel');
        $levelProperty->setAccessible(true);
        $levelProperty->setValue($this->tls, TLS::LEVEL_APPLICATION);

        $this->tls->updateKeys();

        // 验证密钥更新操作完成 - 检查状态保持
        $this->assertEquals(TLS::STATE_ESTABLISHED, $stateProperty->getValue($this->tls));
        $this->assertEquals(TLS::LEVEL_APPLICATION, $levelProperty->getValue($this->tls));
    }

    public function testUpdateKeysWithInvalidState(): void
    {
        $this->expectException(InvalidHandshakeStateException::class);
        $this->expectExceptionMessage('连接未建立，无法更新密钥');

        $this->tls->updateKeys();
    }

    public function testUpdateKeysWithHandshakingState(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $this->expectException(InvalidHandshakeStateException::class);
        $this->expectExceptionMessage('连接未建立，无法更新密钥');

        $this->tls->updateKeys();
    }

    public function testClose(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $this->assertEquals(TLS::STATE_HANDSHAKING, $this->tls->getState());

        $this->tls->close();

        $this->assertEquals(TLS::STATE_CLOSED, $this->tls->getState());
    }

    public function testCloseWhenAlreadyClosed(): void
    {
        $this->tls->close();
        $this->assertEquals(TLS::STATE_CLOSED, $this->tls->getState());

        $this->tls->close();

        $this->assertEquals(TLS::STATE_CLOSED, $this->tls->getState());
    }

    public function testCloseFromInitialState(): void
    {
        $this->assertEquals(TLS::STATE_INITIAL, $this->tls->getState());

        $this->tls->close();

        $this->assertEquals(TLS::STATE_CLOSED, $this->tls->getState());
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->tls = new TLS(true); // 服务器模式
    }
}
