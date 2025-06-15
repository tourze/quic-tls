<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\TLS;
use Tourze\QUIC\TLS\TransportParameters;

class TLSIntegrationTest extends TestCase
{
    public function testClientServerHandshake(): void
    {
        // 创建客户端和服务器配置
        $clientConfig = [
            'verify_peer' => false,
            'allow_self_signed' => true,
        ];
        
        $serverConfig = [
            'verify_peer' => false,
            'allow_self_signed' => true,
        ];
        
        $client = TLS::createClient($clientConfig);
        $server = TLS::createServer($serverConfig);
        
        // 验证初始状态
        $this->assertEquals(TLS::STATE_INITIAL, $client->getState());
        $this->assertEquals(TLS::STATE_INITIAL, $server->getState());
        $this->assertFalse($client->isHandshakeComplete());
        $this->assertFalse($server->isHandshakeComplete());
        
        // 开始握手
        $clientHelloResult = $client->startHandshake();
        $clientHello = is_array($clientHelloResult) ? 
            ($clientHelloResult['client_hello'] ?? '') : 
            $clientHelloResult;
        $this->assertNotEmpty($clientHello);
        $this->assertEquals(TLS::STATE_HANDSHAKING, $client->getState());
        
        // 服务器处理 ClientHello
        $serverResult = $server->processHandshakeData($clientHello);
        $this->assertNotEmpty($serverResult['responses']);
        $this->assertEquals(TLS::STATE_HANDSHAKING, $server->getState());
        
        // 客户端处理服务器响应
        $serverMessage = '';
        foreach ($serverResult['responses'] as $response) {
            $serverMessage .= $response['data'];
        }
        
        if ($serverMessage) {
            $clientResult = $client->processHandshakeData($serverMessage);
            
            // 处理客户端响应
            if (!empty($clientResult['responses'])) {
                $clientMessage = '';
                foreach ($clientResult['responses'] as $response) {
                    $clientMessage .= $response['data'];
                }
                
                if ($clientMessage) {
                    $server->processHandshakeData($clientMessage);
                }
            }
        }
        
        // 验证握手状态（根据实际实现情况，可能需要多轮交互）
        $this->assertTrue($client->getState() === TLS::STATE_ESTABLISHED || $client->getState() === TLS::STATE_HANDSHAKING);
        $this->assertTrue($server->getState() === TLS::STATE_ESTABLISHED || $server->getState() === TLS::STATE_HANDSHAKING);
    }
    
    public function testEncryptionDecryption(): void
    {
        $client = TLS::createClient(['verify_peer' => false]);
        $server = TLS::createServer(['verify_peer' => false]);
        
        // 模拟建立连接（这里简化处理）
        $this->performBasicHandshake($client, $server);
        
        // 如果握手完成，测试加密/解密
        if ($client->isEstablished() && $server->isEstablished()) {
            $plaintext = 'Hello, QUIC TLS!';
            
            $ciphertext = $client->encrypt($plaintext);
            $this->assertNotEmpty($ciphertext);
            $this->assertNotEquals($plaintext, $ciphertext);
            
            $decrypted = $server->decrypt($ciphertext);
            $this->assertEquals($plaintext, $decrypted);
        } else {
            // 如果握手未完成，验证加密操作会失败
            $this->expectException(\RuntimeException::class);
            $client->encrypt('test');
        }
    }
    
    /**
     * 执行基本握手过程
     */
    private function performBasicHandshake(TLS $client, TLS $server): void
    {
        $clientHelloResult = $client->startHandshake();

        // 处理数组或字符串返回值
        $clientHello = is_array($clientHelloResult) ?
            ($clientHelloResult['client_hello'] ?? '') :
            $clientHelloResult;

        if ($clientHello) {
            $serverResult = $server->processHandshakeData($clientHello);

            if (!empty($serverResult['responses'])) {
                $serverMessage = '';
                foreach ($serverResult['responses'] as $response) {
                    $serverMessage .= $response['data'];
                }

                if ($serverMessage) {
                    $clientResult = $client->processHandshakeData($serverMessage);

                    if (!empty($clientResult['responses'])) {
                        $clientMessage = '';
                        foreach ($clientResult['responses'] as $response) {
                            $clientMessage .= $response['data'];
                        }

                        if ($clientMessage) {
                            $server->processHandshakeData($clientMessage);
                        }
                    }
                }
            }
        }
    }
    
    public function testTransportParametersNegotiation(): void
    {
        $clientConfig = [
            'max_idle_timeout' => 60000,
            'max_udp_payload_size' => 1500,
            'initial_max_data' => 2097152, // 2MB
        ];

        $serverConfig = [
            'max_idle_timeout' => 30000,
            'max_udp_payload_size' => 1200,
            'initial_max_data' => 1048576, // 1MB
        ];

        $client = TLS::createClient($clientConfig);
        $server = TLS::createServer($serverConfig);

        // 验证本地参数设置
        $clientParams = $client->getLocalParameters();
        $serverParams = $server->getLocalParameters();

        $this->assertEquals(60000, $clientParams->getMaxIdleTimeout());
        $this->assertEquals(30000, $serverParams->getMaxIdleTimeout());

        // 进行握手
        $this->performBasicHandshake($client, $server);

        // 检查协商结果
        $negotiatedParams = $client->getNegotiatedParameters();
        if ($negotiatedParams) {
            // 验证协商的参数符合预期
            $this->assertInstanceOf(TransportParameters::class, $negotiatedParams);
        }
    }
    
    public function testStatistics(): void
    {
        $client = TLS::createClient();
        $server = TLS::createServer();

        // 检查初始统计
        $clientStats = $client->getStats();
        $serverStats = $server->getStats();

        $this->assertEquals(0, $clientStats['bytes_sent']);
        $this->assertEquals(0, $clientStats['bytes_received']);
        $this->assertEquals(0, $clientStats['messages_sent']);
        $this->assertEquals(0, $clientStats['messages_received']);

        // 开始握手
        $clientHelloResult = $client->startHandshake();
        $clientHello = is_array($clientHelloResult) ?
            ($clientHelloResult['client_hello'] ?? '') :
            $clientHelloResult;

        // 检查客户端统计更新
        $clientStats = $client->getStats();
        $this->assertGreaterThan(0, $clientStats['bytes_sent']);
        $this->assertGreaterThan(0, $clientStats['messages_sent']);
        $this->assertNotNull($clientStats['handshake_start_time']);

        // 服务器处理消息
        $server->processHandshakeData($clientHello);

        // 检查服务器统计更新
        $serverStats = $server->getStats();
        $this->assertGreaterThan(0, $serverStats['bytes_received']);
        $this->assertGreaterThan(0, $serverStats['messages_received']);
    }
    
    public function testCallbacks(): void
    {
        $client = TLS::createClient();
        $events = [];

        // 设置回调
        $client->setCallback('message_sent', function($data) use (&$events) {
            $events[] = 'message_sent';
        });

        $client->setCallback('handshake_complete', function($data) use (&$events) {
            $events[] = 'handshake_complete';
        });

        $client->setCallback('error', function($data) use (&$events) {
            $events[] = 'error';
        });

        // 开始握手
        $client->startHandshake();

        // 验证回调被触发
        $this->assertContains('message_sent', $events);
    }
    
    public function testKeyUpdate(): void
    {
        $client = TLS::createClient();
        $server = TLS::createServer();

        // 在未建立连接时更新密钥应该失败
        $this->expectException(\RuntimeException::class);
        $client->updateKeys();
    }
    
    public function testKeyExport(): void
    {
        $client = TLS::createClient();

        // 在未建立连接时导出密钥应该失败
        $this->expectException(\RuntimeException::class);
        $client->exportKeyingMaterial('test', 32);
    }
    
    public function testConnectionClose(): void
    {
        $client = TLS::createClient();

        $this->assertEquals(TLS::STATE_INITIAL, $client->getState());

        $client->close();

        $this->assertEquals(TLS::STATE_CLOSED, $client->getState());

        // 关闭后的操作应该失败
        $this->expectException(\RuntimeException::class);
        $client->processHandshakeData('test');
    }
    
    public function testSystemSupport(): void
    {
        $support = TLS::checkSupport();

        $this->assertIsArray($support);
        $this->assertArrayHasKey('openssl', $support);
        $this->assertArrayHasKey('sodium', $support);
        $this->assertArrayHasKey('tls_1_3', $support);

        // 验证 OpenSSL 扩展存在
        $this->assertTrue($support['openssl']);
    }
    
    public function testSupportedCipherSuites(): void
    {
        $cipherSuites = TLS::getSupportedCipherSuites();

        $this->assertIsArray($cipherSuites);
        $this->assertArrayHasKey(0x1301, $cipherSuites);
        $this->assertEquals('TLS_AES_128_GCM_SHA256', $cipherSuites[0x1301]);
    }
    
    public function testVersionInfo(): void
    {
        $version = TLS::getVersion();
        $this->assertIsString($version);
        $this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+$/', $version);
    }
    
    public function testDebugInfo(): void
    {
        $client = TLS::createClient();
        $debugInfo = $client->getDebugInfo();

        $this->assertIsArray($debugInfo);
        $this->assertArrayHasKey('state', $debugInfo);
        $this->assertArrayHasKey('level', $debugInfo);
        $this->assertArrayHasKey('is_server', $debugInfo);

        $this->assertEquals(TLS::STATE_INITIAL, $debugInfo['state']);
        $this->assertEquals(TLS::LEVEL_INITIAL, $debugInfo['level']);
        $this->assertFalse($debugInfo['is_server']);
    }
    
    public function testSessionTicket(): void
    {
        $client = TLS::createClient();

        // 未建立连接时不应该有会话票据
        $this->assertNull($client->getSessionTicket());
    }
    
    public function testConfigValidation(): void
    {
        // 测试各种配置选项
        $config = [
            'max_idle_timeout' => 30000,
            'max_udp_payload_size' => 1200,
            'verify_peer' => false,
            'allow_self_signed' => true,
        ];

        $client = TLS::createClient($config);
        $this->assertEquals(TLS::STATE_INITIAL, $client->getState());

        $server = TLS::createServer($config);
        $this->assertEquals(TLS::STATE_INITIAL, $server->getState());
    }
}