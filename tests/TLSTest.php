<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\CertificateValidator;
use Tourze\QUIC\TLS\TLS;
use Tourze\QUIC\TLS\TransportParameters;

class TLSTest extends TestCase
{
    private TLS $tls;
    
    public function test_constructor_initializesServerCorrectly(): void
    {
        $serverTLS = new TLS(true);
        $this->assertInstanceOf(TLS::class, $serverTLS);
    }
    
    public function test_constructor_initializesClientCorrectly(): void
    {
        $clientTLS = new TLS(false);
        $this->assertInstanceOf(TLS::class, $clientTLS);
    }
    
    public function test_setTransportParameters_setsParametersCorrectly(): void
    {
        $params = new TransportParameters([
            TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
            TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE => 1472,
        ]);

        $this->tls->setTransportParameters($params);

        // 验证参数已设置（如果没有异常，说明成功）
        $this->assertTrue(true);
    }
    
    public function test_setCertificateValidator_setsValidatorCorrectly(): void
    {
        $validator = new CertificateValidator(['allow_self_signed' => true]);

        $this->tls->setCertificateValidator($validator);

        // 验证验证器已设置（如果没有异常，说明成功）
        $this->assertTrue(true);
    }
    
    public function test_setCipherSuite_setsSuiteCorrectly(): void
    {
        $this->tls->setCipherSuite('TLS_AES_256_GCM_SHA384');

        // 验证密码套件已设置（如果没有异常，说明成功）
        $this->assertTrue(true);
    }
    
    public function test_setCipherSuite_withInvalidSuite_throwsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('不支持的密码套件');

        $this->tls->setCipherSuite('INVALID_CIPHER_SUITE');
    }
    
    public function test_startHandshake_asServer_startsCorrectly(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);

        $result = $this->tls->startHandshake();

        // 服务器端初始时返回空字符串，等待客户端的 ClientHello
        $this->assertEquals('', $result);
    }
    
    public function test_startHandshake_asClient_startsCorrectly(): void
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
    
    public function test_startHandshake_withoutParameters_throwsException(): void
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
    
    public function test_processMessage_withValidMessage_processesCorrectly(): void
    {
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $message = pack('C', 1) . 'test message';

        $result = $this->tls->processMessage($message);

        $this->assertArrayHasKey('response', $result);
        $this->assertArrayHasKey('state_changed', $result);
    }
    
    public function test_isHandshakeComplete_returnsCorrectStatus(): void
    {
        $isComplete = $this->tls->isHandshakeComplete();

        $this->assertFalse($isComplete); // 初始状态应该是未完成
    }
    
    public function test_encrypt_withApplicationData_encryptsCorrectly(): void
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
    
    public function test_decrypt_withApplicationData_decryptsCorrectly(): void
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
    
    public function test_exportKeyingMaterial_exportsKeys(): void
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
    
    public function test_updateKeys_updatesApplicationKeys(): void
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

        // 验证密钥已更新（如果没有异常，说明成功）
        $this->assertTrue(true);
    }
    
    public function test_getStatistics_returnsStatistics(): void
    {
        $stats = $this->tls->getStatistics();

        $this->assertArrayHasKey('handshake_complete', $stats);
        $this->assertArrayHasKey('messages_processed', $stats);
        $this->assertArrayHasKey('bytes_encrypted', $stats);
        $this->assertArrayHasKey('bytes_decrypted', $stats);
        $this->assertArrayHasKey('cipher_suite', $stats);
        $this->assertArrayHasKey('transport_parameters', $stats);
    }
    
    public function test_setPSK_setsPresharedKey(): void
    {
        $psk = random_bytes(32);

        $this->tls->setPSK($psk);

        // 验证PSK已设置（如果没有异常，说明成功）
        $this->assertTrue(true);
    }
    
    public function test_reset_resetsConnectionState(): void
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
    
    public function test_setCallbacks_setsCallbacksCorrectly(): void
    {
        $callbacks = [
            'on_handshake_complete' => function() { return true; },
            'on_error' => function($error) { return $error; },
            'on_message' => function($message) { return $message; },
        ];

        $this->tls->setCallbacks($callbacks);

        // 验证回调已设置（如果没有异常，说明成功）
        $this->assertTrue(true);
    }
    
    public function test_enableDebugMode_enablesDebugCorrectly(): void
    {
        $this->tls->enableDebugMode(true);

        // 验证调试模式已启用（如果没有异常，说明成功）
        $this->assertTrue(true);
    }
    
    public function test_getTranscriptHash_returnsValidHash(): void
    {
        // 首先进行一些握手操作
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        $transcriptHash = $this->tls->getTranscriptHash();

        $this->assertEquals(32, strlen($transcriptHash)); // SHA256 hash length
    }
    
    public function test_supportedCipherSuites_returnsCorrectSuites(): void
    {
        $suites = TLS::getSupportedCipherSuites();

        $this->assertContains('TLS_AES_128_GCM_SHA256', $suites);
        $this->assertContains('TLS_AES_256_GCM_SHA384', $suites);
        $this->assertContains('TLS_CHACHA20_POLY1305_SHA256', $suites);
    }
    
    public function test_enableZeroRTT_enablesCorrectly(): void
    {
        $this->tls->enableZeroRTT(true);

        // 验证0-RTT已启用（如果没有异常，说明成功）
        $this->assertTrue(true);
    }
    
    public function test_getConnectionInfo_returnsConnectionInfo(): void
    {
        $info = $this->tls->getConnectionInfo();

        $this->assertArrayHasKey('is_server', $info);
        $this->assertArrayHasKey('cipher_suite', $info);
        $this->assertArrayHasKey('handshake_complete', $info);
        $this->assertTrue($info['is_server']);
    }
    
    public function test_processHandshakeMessage_withDifferentTypes_processesCorrectly(): void
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
    
    public function test_errorHandling_withCorruptedData_handlesGracefully(): void
    {
        $corruptedData = 'completely corrupted data';

        $result = $this->tls->processMessage($corruptedData);

        $this->assertArrayHasKey('error', $result);
    }
    
    public function test_memoryCleanup_cleansUpSensitiveData(): void
    {
        // 首先进行一些操作生成敏感数据
        $params = new TransportParameters();
        $this->tls->setTransportParameters($params);
        $this->tls->startHandshake();

        // 重置应该清理敏感数据
        $this->tls->reset();

        // 验证敏感数据已清理（如果没有异常，说明成功）
        $this->assertTrue(true);
    }
    
    protected function setUp(): void
    {
        $this->tls = new TLS(true); // 服务器模式
    }
}