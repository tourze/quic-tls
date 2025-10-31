<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\KeyScheduler;

/**
 * @internal
 */
#[CoversClass(KeyScheduler::class)]
final class KeySchedulerTest extends TestCase
{
    private KeyScheduler $keyScheduler;

    public function testDefaultCipherSuite(): void
    {
        $this->assertEquals('TLS_AES_128_GCM_SHA256', $this->keyScheduler->getCipherSuite());
    }

    public function testSetCipherSuite(): void
    {
        $this->keyScheduler->setCipherSuite('TLS_AES_256_GCM_SHA384');
        $this->assertEquals('TLS_AES_256_GCM_SHA384', $this->keyScheduler->getCipherSuite());
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
    }

    public function testEarlySecretWithoutPSK(): void
    {
        // 不设置PSK时，Early Secret应该使用默认值
        $earlySecret = $this->keyScheduler->getEarlySecret();
        $this->assertNotEmpty($earlySecret);
        $this->assertEquals(32, strlen($earlySecret)); // SHA256 输出长度
    }

    public function testHandshakeSecretDerivation(): void
    {
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'client hello + server hello', true);

        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        // 验证握手密钥已设置
        $clientKey = $this->keyScheduler->getHandshakeKey(false);
        $serverKey = $this->keyScheduler->getHandshakeKey(true);

        $this->assertNotNull($clientKey);
        $this->assertNotNull($serverKey);
        $this->assertNotEquals($clientKey, $serverKey);
        $this->assertEquals(32, strlen($clientKey));
        $this->assertEquals(32, strlen($serverKey));
    }

    public function testMasterSecretDerivation(): void
    {
        // 先设置握手密钥
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'handshake messages', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        // 派生主密钥
        $masterSecret = $this->keyScheduler->deriveMasterSecret();
        $this->assertNotEmpty($masterSecret);
        $this->assertEquals(32, strlen($masterSecret)); // SHA256 输出长度
    }

    public function testApplicationSecretDerivation(): void
    {
        // 设置握手密钥和主密钥
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'handshake messages', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);
        $this->keyScheduler->deriveMasterSecret();

        // 派生应用层密钥
        $appTranscriptHash = hash('sha256', 'application messages', true);
        $appSecrets = $this->keyScheduler->deriveApplicationSecrets($appTranscriptHash);

        $this->assertArrayHasKey('client_application_traffic_secret_0', $appSecrets);
        $this->assertArrayHasKey('server_application_traffic_secret_0', $appSecrets);

        $clientAppKey = $appSecrets['client_application_traffic_secret_0'];
        $serverAppKey = $appSecrets['server_application_traffic_secret_0'];

        $this->assertNotNull($clientAppKey);
        $this->assertNotNull($serverAppKey);
        $this->assertEquals(32, strlen($clientAppKey));
        $this->assertEquals(32, strlen($serverAppKey));
        $this->assertNotEquals($clientAppKey, $serverAppKey);
    }

    public function testHkdfExpandLabel(): void
    {
        $secret = random_bytes(32);
        $label = 'test label';
        $context = 'test context';
        $length = 16;

        $result = $this->keyScheduler->hkdfExpandLabel($secret, $label, $context, $length);

        $this->assertEquals($length, strlen($result));
        $this->assertNotEmpty($result);

        // 相同输入应产生相同输出
        $result2 = $this->keyScheduler->hkdfExpandLabel($secret, $label, $context, $length);
        $this->assertEquals($result, $result2);

        // 不同标签应产生不同输出
        $result3 = $this->keyScheduler->hkdfExpandLabel($secret, 'different label', $context, $length);
        $this->assertNotEquals($result, $result3);
    }

    public function testFinishedMAC(): void
    {
        // 设置握手密钥
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'handshake transcript', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        // 计算Finished MAC
        $serverMAC = $this->keyScheduler->computeFinishedMAC($transcriptHash, true);
        $clientMAC = $this->keyScheduler->computeFinishedMAC($transcriptHash, false);

        $this->assertNotEmpty($serverMAC);
        $this->assertNotEmpty($clientMAC);
        $this->assertEquals(32, strlen($serverMAC)); // SHA256 MAC长度
        $this->assertEquals(32, strlen($clientMAC));
        $this->assertNotEquals($serverMAC, $clientMAC); // 服务端和客户端MAC应该不同
    }

    public function testQuicKeyDerivation(): void
    {
        $trafficSecret = random_bytes(32);

        $quicKeys = $this->keyScheduler->deriveQuicKeys($trafficSecret);

        $this->assertArrayHasKey('key', $quicKeys);
        $this->assertArrayHasKey('iv', $quicKeys);
        $this->assertArrayHasKey('header_protection', $quicKeys);

        $this->assertEquals(16, strlen($quicKeys['key'])); // AES-128 key length
        $this->assertEquals(12, strlen($quicKeys['iv'])); // GCM IV length
        $this->assertEquals(16, strlen($quicKeys['header_protection'])); // Header protection key length
    }

    public function testQuicKeyDerivationDifferentCiphers(): void
    {
        // 测试AES-128
        $this->keyScheduler->setCipherSuite('TLS_AES_128_GCM_SHA256');
        $trafficSecret = random_bytes(32);
        $keys128 = $this->keyScheduler->deriveQuicKeys($trafficSecret);

        // 测试AES-256
        $this->keyScheduler->setCipherSuite('TLS_AES_256_GCM_SHA384');
        $keys256 = $this->keyScheduler->deriveQuicKeys($trafficSecret);

        // 不同算法应产生不同长度的密钥
        $this->assertEquals(16, strlen($keys128['key'])); // AES-128
        $this->assertEquals(32, strlen($keys256['key'])); // AES-256

        // 但IV长度应该相同
        $this->assertEquals(12, strlen($keys128['iv']));
        $this->assertEquals(12, strlen($keys256['iv']));
    }

    public function testKeyUpdate(): void
    {
        // 设置应用层密钥
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'handshake messages', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);
        $this->keyScheduler->deriveMasterSecret();

        $appTranscriptHash = hash('sha256', 'application messages', true);
        $this->keyScheduler->deriveApplicationSecrets($appTranscriptHash);

        // 获取更新前的密钥
        $oldClientKey = $this->keyScheduler->getApplicationKey(false);
        $oldServerKey = $this->keyScheduler->getApplicationKey(true);

        // 执行密钥更新
        $this->keyScheduler->updateKeys();

        // 获取更新后的密钥
        $newClientKey = $this->keyScheduler->getApplicationKey(false);
        $newServerKey = $this->keyScheduler->getApplicationKey(true);

        // 密钥应该已更新
        $this->assertNotNull($oldClientKey);
        $this->assertNotNull($oldServerKey);
        $this->assertNotNull($newClientKey);
        $this->assertNotNull($newServerKey);
        $this->assertNotEquals($oldClientKey, $newClientKey);
        $this->assertNotEquals($oldServerKey, $newServerKey);
    }

    public function testExportKeyingMaterial(): void
    {
        // 设置完整的密钥层次
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'handshake messages', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);
        $masterSecret = $this->keyScheduler->deriveMasterSecret();

        $appTranscriptHash = hash('sha256', 'application messages', true);
        $this->keyScheduler->deriveApplicationSecrets($appTranscriptHash);

        // 导出密钥材料
        $exporterSecret = $this->keyScheduler->getExporterMasterSecret($appTranscriptHash);
        $keyMaterial = $this->keyScheduler->exportKeyingMaterial($exporterSecret, 'test label', 'test context', 32);

        $this->assertEquals(32, strlen($keyMaterial));
        $this->assertNotEmpty($keyMaterial);

        // 相同参数应产生相同输出
        $keyMaterial2 = $this->keyScheduler->exportKeyingMaterial($exporterSecret, 'test label', 'test context', 32);
        $this->assertEquals($keyMaterial, $keyMaterial2);

        // 不同标签应产生不同输出
        $keyMaterial3 = $this->keyScheduler->exportKeyingMaterial($exporterSecret, 'different label', 'test context', 32);
        $this->assertNotEquals($keyMaterial, $keyMaterial3);
    }

    public function testResumptionMasterSecret(): void
    {
        // 设置完整的密钥层次
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'handshake messages', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);
        $this->keyScheduler->deriveMasterSecret();

        $appTranscriptHash = hash('sha256', 'application messages', true);
        $this->keyScheduler->deriveApplicationSecrets($appTranscriptHash);

        // 获取会话恢复主密钥
        $resumptionSecret = $this->keyScheduler->deriveResumptionMasterSecret($appTranscriptHash);

        $this->assertNotEmpty($resumptionSecret);
        $this->assertEquals(32, strlen($resumptionSecret)); // SHA256 输出长度
    }

    public function testKeyScheduleOrder(): void
    {
        // 密钥调度必须按正确顺序进行
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'messages', true);

        // 1. 首先派生握手密钥
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);
        $this->assertNotNull($this->keyScheduler->getHandshakeKey(false));

        // 2. 然后派生主密钥
        $masterSecret = $this->keyScheduler->deriveMasterSecret();
        $this->assertNotEmpty($masterSecret);

        // 3. 最后派生应用层密钥
        $appSecrets = $this->keyScheduler->deriveApplicationSecrets($transcriptHash);
        $this->assertArrayHasKey('client_application_traffic_secret', $appSecrets);

        // 4. 现在可以派生QUIC密钥
        $clientTrafficSecret = $appSecrets['client_application_traffic_secret'];
        $this->assertNotNull($clientTrafficSecret);
        $quicKeys = $this->keyScheduler->deriveQuicKeys($clientTrafficSecret);
        $this->assertArrayHasKey('key', $quicKeys);
    }

    public function testDifferentHashAlgorithms(): void
    {
        $secret = random_bytes(32);
        $label = 'test';
        $context = '';
        $length = 32;

        // SHA256
        $this->keyScheduler->setCipherSuite('TLS_AES_128_GCM_SHA256');
        $result256 = $this->keyScheduler->hkdfExpandLabel($secret, $label, $context, $length);

        // SHA384
        $this->keyScheduler->setCipherSuite('TLS_AES_256_GCM_SHA384');
        $result384 = $this->keyScheduler->hkdfExpandLabel($secret, $label, $context, $length);

        // 不同哈希算法应该产生不同结果
        $this->assertNotEquals($result256, $result384);
    }

    public function testDeriveEarlyDataKeys(): void
    {
        $psk = random_bytes(32);
        $this->keyScheduler->setEarlySecret($psk);

        $earlyKeys = $this->keyScheduler->deriveEarlyDataKeys();

        $this->assertArrayHasKey('client_early_traffic_secret', $earlyKeys);
        $this->assertArrayHasKey('early_exporter_master_secret', $earlyKeys);

        $this->assertEquals(32, strlen($earlyKeys['client_early_traffic_secret']));
        $this->assertEquals(32, strlen($earlyKeys['early_exporter_master_secret']));
    }

    public function testComputeFinishedMAC(): void
    {
        // 设置握手密钥
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'test transcript', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        // 计算服务端 Finished MAC
        $serverMAC = $this->keyScheduler->computeFinishedMAC($transcriptHash, true);
        $this->assertNotEmpty($serverMAC);
        $this->assertEquals(32, strlen($serverMAC)); // SHA256 输出长度

        // 计算客户端 Finished MAC
        $clientMAC = $this->keyScheduler->computeFinishedMAC($transcriptHash, false);
        $this->assertNotEmpty($clientMAC);
        $this->assertEquals(32, strlen($clientMAC));

        // 客户端和服务端的 MAC 应该不同
        $this->assertNotEquals($clientMAC, $serverMAC);
    }

    public function testDeriveApplicationSecrets(): void
    {
        // 先设置握手密钥
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'handshake transcript', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        // 设置主密钥
        $masterSecret = $this->keyScheduler->deriveMasterSecret();

        // 派生应用层密钥
        $appTranscriptHash = hash('sha256', 'application transcript', true);
        $appSecrets = $this->keyScheduler->deriveApplicationSecrets($appTranscriptHash);

        $this->assertArrayHasKey('client_application_traffic_secret', $appSecrets);
        $this->assertArrayHasKey('server_application_traffic_secret', $appSecrets);
        $this->assertNotNull($appSecrets['client_application_traffic_secret']);
        $this->assertNotNull($appSecrets['server_application_traffic_secret']);
        $this->assertEquals(32, strlen($appSecrets['client_application_traffic_secret']));
        $this->assertEquals(32, strlen($appSecrets['server_application_traffic_secret']));
    }

    public function testDeriveHandshakeSecrets(): void
    {
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'test transcript', true);

        // deriveHandshakeSecrets 没有返回值，只是设置内部状态
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        // 验证握手密钥已设置（通过获取密钥来验证）
        $clientKey = $this->keyScheduler->getHandshakeKey(false);
        $serverKey = $this->keyScheduler->getHandshakeKey(true);

        $this->assertNotNull($clientKey);
        $this->assertNotNull($serverKey);
        $this->assertNotEquals($clientKey, $serverKey);
    }

    public function testDeriveHandshakeSecretsWithResult(): void
    {
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'test transcript', true);

        // 使用带结果的握手密钥派生
        $result = $this->keyScheduler->deriveHandshakeSecretsWithResult($sharedSecret, $transcriptHash);

        $this->assertNotEmpty($result);
        $this->assertIsArray($result);
    }

    public function testDeriveMasterSecret(): void
    {
        // 先设置握手密钥
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'handshake transcript', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        $masterSecret = $this->keyScheduler->deriveMasterSecret();

        $this->assertNotEmpty($masterSecret);
        $this->assertEquals(32, strlen($masterSecret)); // SHA256 输出长度
    }

    public function testDeriveQuicKeys(): void
    {
        // QUIC 密钥需要流量密钥作为参数
        $trafficSecret = random_bytes(32);

        // 派生 QUIC 密钥
        $quicKeys = $this->keyScheduler->deriveQuicKeys($trafficSecret);

        $this->assertArrayHasKey('key', $quicKeys);
        $this->assertArrayHasKey('iv', $quicKeys);
        $this->assertArrayHasKey('header_protection', $quicKeys);
    }

    public function testDeriveResumptionMasterSecret(): void
    {
        // 先设置握手密钥
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'handshake transcript', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        // 派生主密钥
        $this->keyScheduler->deriveMasterSecret();

        $resumptionSecret = $this->keyScheduler->deriveResumptionMasterSecret($transcriptHash);

        $this->assertNotEmpty($resumptionSecret);
        $this->assertEquals(32, strlen($resumptionSecret));
    }

    public function testReset(): void
    {
        // 先设置一些密钥
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'test transcript', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        // 重置密钥调度器
        $this->keyScheduler->reset();

        // 验证状态已重置
        $this->assertFalse($this->keyScheduler->isReady());
    }

    public function testUpdateKeys(): void
    {
        // 先设置应用层密钥
        $sharedSecret = random_bytes(32);
        $transcriptHash = hash('sha256', 'handshake transcript', true);
        $this->keyScheduler->deriveHandshakeSecrets($sharedSecret, $transcriptHash);

        $this->keyScheduler->deriveMasterSecret();

        $appTranscriptHash = hash('sha256', 'application transcript', true);
        $this->keyScheduler->deriveApplicationSecrets($appTranscriptHash);

        // 获取更新前的密钥状态
        $oldClientKey = $this->keyScheduler->getApplicationKey(false);
        $oldServerKey = $this->keyScheduler->getApplicationKey(true);

        // 更新密钥
        $this->keyScheduler->updateKeys();

        // 验证密钥更新操作完成（通过比较更新前后的密钥）
        $newClientKey = $this->keyScheduler->getApplicationKey(false);
        $newServerKey = $this->keyScheduler->getApplicationKey(true);

        if (null !== $oldClientKey && null !== $oldServerKey) {
            $this->assertNotEquals($oldClientKey, $newClientKey);
            $this->assertNotEquals($oldServerKey, $newServerKey);
        } else {
            $this->assertNull($oldClientKey);
            $this->assertNull($oldServerKey);
        }

        $this->assertNotNull($newClientKey);
        $this->assertNotNull($newServerKey);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->keyScheduler = new KeyScheduler();
    }
}
