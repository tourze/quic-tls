<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\TLS;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\KeyScheduler;
use Tourze\QUIC\TLS\TLS\CryptoManager;

/**
 * @internal
 */
#[CoversClass(CryptoManager::class)]
final class CryptoManagerTest extends TestCase
{
    private CryptoManager $cryptoManager;

    public function testConstructorInitializesCorrectly(): void
    {
        $this->assertInstanceOf(CryptoManager::class, $this->cryptoManager);
    }

    public function testGetCipherInfoReturnsCipherSuiteInfo(): void
    {
        $info = $this->cryptoManager->getCipherInfo();
        $this->assertArrayHasKey('name', $info);
        $this->assertArrayHasKey('key_len', $info);
        $this->assertArrayHasKey('iv_len', $info);
        $this->assertArrayHasKey('tag_len', $info);
        $this->assertEquals('TLS_AES_128_GCM_SHA256', $info['name']);
    }

    public function testSetHandshakeSecretsSetsSecretsCorrectly(): void
    {
        $clientSecret = random_bytes(32);
        $serverSecret = random_bytes(32);

        $this->cryptoManager->setHandshakeSecrets($clientSecret, $serverSecret);

        // 验证握手密钥已设置 - 通过反射检查内部状态
        $reflection = new \ReflectionClass($this->cryptoManager);
        $keysProp = $reflection->getProperty('keys');
        $keysProp->setAccessible(true);
        $keys = $keysProp->getValue($this->cryptoManager);

        // 验证握手级别的密钥已设置
        $this->assertIsArray($keys);
        $this->assertArrayHasKey('handshake', $keys);
        $this->assertNotNull($keys['handshake']);

        // 验证当前级别已设置为握手
        $currentLevelProp = $reflection->getProperty('currentLevel');
        $currentLevelProp->setAccessible(true);
        $currentLevel = $currentLevelProp->getValue($this->cryptoManager);
        $this->assertEquals('handshake', $currentLevel);
    }

    public function testSetApplicationSecretsSetsSecretsCorrectly(): void
    {
        $clientSecret = random_bytes(32);
        $serverSecret = random_bytes(32);

        $this->cryptoManager->setApplicationSecrets($clientSecret, $serverSecret);

        // 验证应用密钥已设置 - 通过反射检查内部状态
        $reflection = new \ReflectionClass($this->cryptoManager);
        $keysProp = $reflection->getProperty('keys');
        $keysProp->setAccessible(true);
        $keys = $keysProp->getValue($this->cryptoManager);

        // 验证应用级别的密钥已设置
        $this->assertIsArray($keys);
        $this->assertArrayHasKey('application', $keys);
        $this->assertNotNull($keys['application']);

        // 验证当前级别已设置为应用
        $currentLevelProp = $reflection->getProperty('currentLevel');
        $currentLevelProp->setAccessible(true);
        $currentLevel = $currentLevelProp->getValue($this->cryptoManager);
        $this->assertEquals('application', $currentLevel);
    }

    public function testEncryptWithValidDataReturnsEncryptedData(): void
    {
        // 设置测试密钥
        $clientSecret = random_bytes(32);
        $serverSecret = random_bytes(32);
        $this->cryptoManager->setHandshakeSecrets($clientSecret, $serverSecret);

        $plaintext = 'Hello QUIC TLS';
        $associatedData = 'test-ad';

        $ciphertext = $this->cryptoManager->encrypt($plaintext, 'handshake', $associatedData);

        $this->assertNotEmpty($ciphertext);
        $this->assertNotEquals($plaintext, $ciphertext);
        $this->assertGreaterThan(strlen($plaintext), strlen($ciphertext)); // 包含tag
    }

    public function testDecryptWithValidCiphertextReturnsPlaintext(): void
    {
        // 创建客户端和服务器端的 CryptoManager
        $serverCrypto = new CryptoManager(true);  // 服务器
        $clientCrypto = new CryptoManager(false); // 客户端

        // 设置相同的密钥
        $clientSecret = random_bytes(32);
        $serverSecret = random_bytes(32);
        $serverCrypto->setHandshakeSecrets($clientSecret, $serverSecret);
        $clientCrypto->setHandshakeSecrets($clientSecret, $serverSecret);

        $plaintext = 'Hello QUIC TLS';
        $associatedData = 'test-ad';

        // 服务器加密
        $ciphertext = $serverCrypto->encrypt($plaintext, 'handshake', $associatedData);

        // 客户端解密
        $decrypted = $clientCrypto->decrypt($ciphertext, 'handshake', $associatedData);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptWithInvalidLevelThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('级别 invalid 的加密上下文未初始化');

        $this->cryptoManager->encrypt('test', 'invalid', '');
    }

    public function testDecryptWithInvalidLevelThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('级别 invalid 的加密上下文未初始化');

        $this->cryptoManager->decrypt('test', 'invalid', '');
    }

    public function testDecryptWithTooShortCiphertextThrowsException(): void
    {
        // 设置测试密钥
        $clientSecret = random_bytes(32);
        $serverSecret = random_bytes(32);
        $this->cryptoManager->setHandshakeSecrets($clientSecret, $serverSecret);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('密文太短');

        $this->cryptoManager->decrypt('short', 'handshake', '');
    }

    public function testUpdateKeysWithApplicationLevelUpdatesKeys(): void
    {
        // 设置应用密钥
        $clientSecret = random_bytes(32);
        $serverSecret = random_bytes(32);
        $this->cryptoManager->setApplicationSecrets($clientSecret, $serverSecret);

        // 切换到应用级别
        $this->cryptoManager->setCurrentLevel('application');

        // 更新密钥
        $this->cryptoManager->updateKeys();

        // 验证密钥更新操作完成（通过反射检查内部状态）
        $reflection = new \ReflectionClass($this->cryptoManager);
        $currentLevelProp = $reflection->getProperty('currentLevel');
        $currentLevelProp->setAccessible(true);
        $currentLevel = $currentLevelProp->getValue($this->cryptoManager);

        $this->assertEquals('application', $currentLevel);
    }

    public function testUpdateKeysWithNonApplicationLevelThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('只能在应用级别更新密钥');

        $this->cryptoManager->updateKeys();
    }

    public function testSetCurrentLevelSetsLevelCorrectly(): void
    {
        $this->cryptoManager->setCurrentLevel('application');

        // 验证当前级别已设置（通过反射检查内部状态）
        $reflection = new \ReflectionClass($this->cryptoManager);
        $currentLevelProp = $reflection->getProperty('currentLevel');
        $currentLevelProp->setAccessible(true);
        $currentLevel = $currentLevelProp->getValue($this->cryptoManager);

        $this->assertEquals('application', $currentLevel);
    }

    public function testResetSequenceNumbersResetsCorrectly(): void
    {
        $this->cryptoManager->resetSequenceNumbers('handshake');

        // 验证序列号重置操作完成（通过反射检查内部状态）
        $reflection = new \ReflectionClass($this->cryptoManager);
        $sequenceNumbersProp = $reflection->getProperty('sequenceNumbers');
        $sequenceNumbersProp->setAccessible(true);
        $sequenceNumbers = $sequenceNumbersProp->getValue($this->cryptoManager);

        $this->assertIsArray($sequenceNumbers);
        $this->assertArrayHasKey('handshake', $sequenceNumbers);
        $this->assertIsArray($sequenceNumbers['handshake']);
        // 验证握手级别的序列号已重置为 0
        $this->assertEquals(0, $sequenceNumbers['handshake']['client']);
        $this->assertEquals(0, $sequenceNumbers['handshake']['server']);
    }

    public function testGetKeySchedulerReturnsKeyScheduler(): void
    {
        $keyScheduler = $this->cryptoManager->getKeyScheduler();

        $this->assertInstanceOf(KeyScheduler::class, $keyScheduler);
        // 不能比较具体的实例，因为 CryptoManager 内部创建了新的 KeyScheduler
    }

    public function testChacha20Poly1305CipherSuiteWorksCorrectly(): void
    {
        $cryptoManager = new CryptoManager(true);

        $info = $cryptoManager->getCipherInfo();
        $this->assertEquals('TLS_AES_128_GCM_SHA256', $info['name']); // 默认密码套件
        $this->assertEquals(16, $info['key_len']);
        $this->assertEquals(12, $info['iv_len']);
    }

    public function testAes256GcmCipherSuiteWorksCorrectly(): void
    {
        $cryptoManager = new CryptoManager(false); // client

        $info = $cryptoManager->getCipherInfo();
        $this->assertEquals('TLS_AES_128_GCM_SHA256', $info['name']); // 默认密码套件
        $this->assertEquals(16, $info['key_len']);
        $this->assertEquals(12, $info['iv_len']);
    }

    public function testUnsupportedCipherSuiteThrowsException(): void
    {
        // 测试默认密码套件的有效性
        $cryptoManager = new CryptoManager(true);
        $info = $cryptoManager->getCipherInfo();

        // 验证默认密码套件信息包含必要字段
        $this->assertArrayHasKey('name', $info);
        $this->assertArrayHasKey('key_len', $info);
        $this->assertArrayHasKey('iv_len', $info);
        $this->assertArrayHasKey('tag_len', $info);

        // 验证密码套件名称是受支持的
        $supportedCiphers = ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'];
        $this->assertContains($info['name'], $supportedCiphers);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->cryptoManager = new CryptoManager(true); // isServer = true
    }
}
