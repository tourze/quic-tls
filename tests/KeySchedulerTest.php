<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\KeyScheduler;

class KeySchedulerTest extends TestCase
{
    private KeyScheduler $keyScheduler;
    
    public function testDefaultCipherSuite(): void
    {
        $this->assertEquals('TLS_AES_128_GCM_SHA256', $this->keyScheduler->getCipherSuite());
    }
    
    public function testSetCipherSuite(): void
    {
        $this->keyScheduler->setCipherSuite('sha384');
        $this->assertEquals('sha384', $this->keyScheduler->getCipherSuite());

        $this->keyScheduler->setCipherSuite('sha512');
        $this->assertEquals('sha512', $this->keyScheduler->getCipherSuite());
    }
    
    public function testInvalidCipherSuite(): void
    {
        $this->expectException(\ValueError::class);
        $this->keyScheduler->setCipherSuite('INVALID_CIPHER');
    }
    
    public function testEarlySecret(): void
    {
        $psk = random_bytes(32);
        $this->keyScheduler->setEarlySecret($psk);

        $earlySecret = $this->keyScheduler->getEarlySecret();
        $this->assertNotEmpty($earlySecret);
        $this->assertEquals(32, strlen($earlySecret)); // SHA256 输出长度
    }
    
    public function testEarlySecretWithoutPSK(): void
    {
        $this->keyScheduler->setEarlySecret('');

        $earlySecret = $this->keyScheduler->getEarlySecret();
        $this->assertNotEmpty($earlySecret);
        $this->assertEquals(32, strlen($earlySecret));
    }
    
    public function testHandshakeSecretDerivation(): void
    {
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'test transcript', true);
        $this->keyScheduler->setEarlySecret('');

        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        $clientKey = $this->keyScheduler->getHandshakeKey(false);
        $serverKey = $this->keyScheduler->getHandshakeKey(true);

        $this->assertNotNull($clientKey);
        $this->assertNotNull($serverKey);
        $this->assertEquals(32, strlen($clientKey));
        $this->assertEquals(32, strlen($serverKey));
    }
    
    public function testMasterSecretDerivation(): void
    {
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'test transcript', true);
        $this->keyScheduler->setEarlySecret('');
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        $masterSecret = $this->keyScheduler->deriveMasterSecret();

        $this->assertNotEmpty($masterSecret);
        $this->assertEquals(32, strlen($masterSecret));
    }
    
    public function testApplicationSecretDerivation(): void
    {
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'test transcript', true);

        $this->keyScheduler->setEarlySecret('');
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);
        $this->keyScheduler->deriveMasterSecret();

        $this->keyScheduler->deriveApplicationSecrets($transcriptHash);

        $clientKey = $this->keyScheduler->getApplicationKey(false);
        $serverKey = $this->keyScheduler->getApplicationKey(true);

        $this->assertNotNull($clientKey);
        $this->assertNotNull($serverKey);
        $this->assertEquals(32, strlen($clientKey));
        $this->assertEquals(32, strlen($serverKey));
    }
    
    public function testHkdfExpandLabel(): void
    {
        $secret = random_bytes(32);
        $label = "test label";
        $context = "test context";
        $length = 16;

        $result = $this->keyScheduler->hkdfExpandLabel($secret, $label, $context, $length);

        $this->assertEquals($length, strlen($result));

        // 相同的输入应该产生相同的输出
        $result2 = $this->keyScheduler->hkdfExpandLabel($secret, $label, $context, $length);
        $this->assertEquals($result, $result2);

        // 不同的输入应该产生不同的输出
        $result3 = $this->keyScheduler->hkdfExpandLabel($secret, "different label", $context, $length);
        $this->assertNotEquals($result, $result3);
    }
    
    public function testFinishedMAC(): void
    {
        $transcriptHash = hash('sha256', 'test transcript', true);
        $isServer = false;

        // 设置必要的密钥
        $this->keyScheduler->setEarlySecret('');
        $this->keyScheduler->deriveHandshakeSecrets(random_bytes(32), $transcriptHash);

        $mac = $this->keyScheduler->computeFinishedMAC($transcriptHash, $isServer);

        $this->assertNotEmpty($mac);
        $this->assertEquals(32, strlen($mac)); // HMAC-SHA256 输出长度

        // 服务器和客户端应该产生不同的 MAC
        $serverMac = $this->keyScheduler->computeFinishedMAC($transcriptHash, true);
        $this->assertNotEquals($mac, $serverMac);
    }
    
    public function testQuicKeyDerivation(): void
    {
        $secret = random_bytes(32);

        $keys = $this->keyScheduler->deriveQuicKeys($secret);

        $this->assertIsArray($keys);
        $this->assertArrayHasKey('key', $keys);
        $this->assertArrayHasKey('iv', $keys);
        $this->assertArrayHasKey('hp', $keys); // header protection

        $this->assertEquals(16, strlen($keys['key'])); // AES-128 密钥长度
        $this->assertEquals(12, strlen($keys['iv']));  // GCM IV 长度
        $this->assertEquals(16, strlen($keys['hp']));  // header protection 密钥长度
    }
    
    public function testQuicKeyDerivationDifferentCiphers(): void
    {
        $secret = random_bytes(32);

        // AES-128-GCM
        $this->keyScheduler->setCipherSuite('TLS_AES_128_GCM_SHA256');
        $keys128 = $this->keyScheduler->deriveQuicKeys($secret);
        $this->assertEquals(16, strlen($keys128['key']));

        // AES-256-GCM
        $this->keyScheduler->setCipherSuite('TLS_AES_256_GCM_SHA384');
        $keys256 = $this->keyScheduler->deriveQuicKeys($secret);
        $this->assertEquals(32, strlen($keys256['key']));

        // ChaCha20-Poly1305
        $this->keyScheduler->setCipherSuite('TLS_CHACHA20_POLY1305_SHA256');
        $keysChacha = $this->keyScheduler->deriveQuicKeys($secret);
        $this->assertEquals(32, strlen($keysChacha['key']));
    }
    
    public function testKeyUpdate(): void
    {
        // 设置应用密钥
        $transcriptHash = hash('sha256', 'test', true);
        $this->keyScheduler->setEarlySecret('');
        $this->keyScheduler->deriveHandshakeSecrets(random_bytes(32), $transcriptHash);
        $this->keyScheduler->deriveMasterSecret();
        $appSecrets = $this->keyScheduler->deriveApplicationSecrets($transcriptHash);

        $originalClientSecret = $appSecrets['client_application_traffic_secret_0'];

        $this->keyScheduler->updateKeys();

        $newSecrets = $this->keyScheduler->getApplicationSecrets();
        $this->assertNotEquals($originalClientSecret, $newSecrets['client']);
    }
    
    public function testExportKeyingMaterial(): void
    {
        $transcriptHash = hash('sha256', 'test', true);
        $this->keyScheduler->setEarlySecret('');
        $this->keyScheduler->deriveHandshakeSecrets(random_bytes(32), $transcriptHash);
        $masterSecret = $this->keyScheduler->deriveMasterSecret();
        $this->keyScheduler->deriveApplicationSecrets($transcriptHash);

        $label = "test export";
        $context = hash('sha256', 'context', true);
        $length = 16;

        $exported = $this->keyScheduler->exportKeyingMaterial($masterSecret, $label, $context, $length);

        $this->assertEquals($length, strlen($exported));

        // 相同参数应该产生相同结果
        $exported2 = $this->keyScheduler->exportKeyingMaterial($masterSecret, $label, $context, $length);
        $this->assertEquals($exported, $exported2);

        // 不同 label 应该产生不同结果
        $exported3 = $this->keyScheduler->exportKeyingMaterial($masterSecret, "different", $context, $length);
        $this->assertNotEquals($exported, $exported3);
    }
    
    public function testResumptionMasterSecret(): void
    {
        $transcriptHash = hash('sha256', 'test', true);
        $this->keyScheduler->setEarlySecret('');
        $this->keyScheduler->deriveHandshakeSecrets(random_bytes(32), $transcriptHash);
        $this->keyScheduler->deriveMasterSecret();

        $resumptionSecret = $this->keyScheduler->deriveResumptionMasterSecret($transcriptHash);

        $this->assertNotEmpty($resumptionSecret);
        $this->assertEquals(32, strlen($resumptionSecret));
    }
    
    public function testKeyScheduleOrder(): void
    {
        // 测试密钥调度的正确顺序
        $psk = random_bytes(32);
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'test', true);

        // 1. Early Secret
        $this->keyScheduler->setEarlySecret($psk);
        $earlySecret = $this->keyScheduler->getEarlySecret();
        $this->assertNotEmpty($earlySecret);

        // 2. Handshake Secret
        $handshakeSecrets = $this->keyScheduler->deriveHandshakeSecretsWithResult($sharedSecret);
        $this->assertNotEmpty($handshakeSecrets['handshake_secret']);

        // 3. Master Secret
        $masterSecret = $this->keyScheduler->deriveMasterSecret();
        $this->assertNotEmpty($masterSecret);

        // 4. Application Secrets
        $appSecrets = $this->keyScheduler->deriveApplicationSecrets($transcriptHash);
        $this->assertNotEmpty($appSecrets['client_application_traffic_secret_0']);

        // 所有密钥应该不同
        $this->assertNotEquals($earlySecret, $handshakeSecrets['handshake_secret']);
        $this->assertNotEquals($handshakeSecrets['handshake_secret'], $masterSecret);
        $this->assertNotEquals($masterSecret, $appSecrets['client_application_traffic_secret_0']);
    }
    
    public function testDifferentHashAlgorithms(): void
    {
        $secret = random_bytes(32);

        // SHA256 (default)
        $this->keyScheduler->setCipherSuite('TLS_AES_128_GCM_SHA256');
        $result256 = $this->keyScheduler->hkdfExpandLabel($secret, "test", "", 16);

        // SHA384
        $this->keyScheduler->setCipherSuite('TLS_AES_256_GCM_SHA384');
        $result384 = $this->keyScheduler->hkdfExpandLabel($secret, "test", "", 16);

        // 不同哈希算法应该产生不同结果
        $this->assertNotEquals($result256, $result384);
    }
    
    public function testEarlyDataKeys(): void
    {
        $psk = random_bytes(32);
        $this->keyScheduler->setEarlySecret($psk);

        $earlyKeys = $this->keyScheduler->deriveEarlyDataKeys();

        $this->assertIsArray($earlyKeys);
        $this->assertArrayHasKey('client_early_traffic_secret', $earlyKeys);
        $this->assertArrayHasKey('early_exporter_master_secret', $earlyKeys);

        $this->assertEquals(32, strlen($earlyKeys['client_early_traffic_secret']));
        $this->assertEquals(32, strlen($earlyKeys['early_exporter_master_secret']));
    }
    
    protected function setUp(): void
    {
        $this->keyScheduler = new KeyScheduler();
    }
}