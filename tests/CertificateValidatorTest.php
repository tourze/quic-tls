<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\CertificateValidator;

class CertificateValidatorTest extends TestCase
{
    private CertificateValidator $validator;
    private string $testCertPem = '';
    private string $testPrivateKeyPem = '';
    
    public function testDefaultConfiguration(): void
    {
        $config = $this->validator->getConfig();

        $this->assertTrue($config['verify_peer']);
        $this->assertTrue($config['verify_peer_name']);
        $this->assertFalse($config['allow_self_signed']);
        $this->assertEquals(7, $config['verify_depth']);
        $this->assertTrue($config['disable_compression']);
        $this->assertNotEmpty($config['ca_file']);
    }
    
    public function testCustomConfiguration(): void
    {
        $customConfig = [
            'verify_peer' => false,
            'allow_self_signed' => true,
            'verify_depth' => 3,
        ];

        $validator = new CertificateValidator($customConfig);
        $config = $validator->getConfig();

        $this->assertFalse($config['verify_peer']);
        $this->assertTrue($config['allow_self_signed']);
        $this->assertEquals(3, $config['verify_depth']);
    }
    
    public function testSelfSignedCertificateValidation(): void
    {
        $validator = new CertificateValidator([
            'verify_peer' => true,
            'allow_self_signed' => true,
        ]);

        $certificates = [$this->testCertPem];
        $result = $validator->validateCertificate($certificates);

        $this->assertTrue($result);
    }
    
    public function testSelfSignedCertificateRejection(): void
    {
        $validator = new CertificateValidator([
            'verify_peer' => true,
            'allow_self_signed' => false,
        ]);

        $certificates = [$this->testCertPem];
        $result = $validator->validateCertificate($certificates);

        $this->assertFalse($result);
    }
    
    public function testCertificateChainValidation(): void
    {
        $validator = new CertificateValidator([
            'allow_self_signed' => true,
        ]);

        // 测试单个证书的链
        $certificates = [$this->testCertPem];
        $result = $validator->validateCertificateChain($certificates);

        $this->assertTrue($result);
    }
    
    public function testInvalidCertificateFormat(): void
    {
        $validator = new CertificateValidator([
            'allow_self_signed' => true,
        ]);

        $invalidCert = "INVALID CERTIFICATE DATA";
        $certificates = [$invalidCert];

        $result = $validator->validateCertificate($certificates);
        $this->assertFalse($result);
    }
    
    public function testEmptyCertificateArray(): void
    {
        $result = $this->validator->validateCertificate([]);
        $this->assertFalse($result);
    }
    
    public function testCertificateExpiration(): void
    {
        // 创建一个已过期的证书（这里模拟测试）
        $validator = new CertificateValidator([
            'allow_self_signed' => true,
        ]);

        // 对于有效的证书，验证其有效期检查
        $certificates = [$this->testCertPem];
        $result = $validator->validateCertificate($certificates);

        // 新创建的证书应该是有效的
        $this->assertTrue($result);
    }
    
    public function testHostnameVerification(): void
    {
        $validator = new CertificateValidator([
            'verify_peer_name' => true,
            'allow_self_signed' => true,
        ]);

        $hostname = 'example.com';
        $result = $validator->verifyHostname($this->testCertPem, $hostname);

        // 我们的测试证书不是为 example.com 签发的，所以应该失败
        $this->assertFalse($result);
    }
    
    public function testHostnameVerificationDisabled(): void
    {
        $validator = new CertificateValidator([
            'verify_peer_name' => false,
            'allow_self_signed' => true,
        ]);

        $hostname = 'example.com';
        $result = $validator->verifyHostname($this->testCertPem, $hostname);

        // 禁用主机名验证时应该返回 true
        $this->assertTrue($result);
    }
    
    public function testWildcardHostnameMatching(): void
    {
        $validator = new CertificateValidator();

        // 测试通配符匹配逻辑
        $this->assertFalse($validator->matchesWildcard('example.com', '*.example.com')); // *.example.com 不匹配 example.com
        $this->assertTrue($validator->matchesWildcard('sub.example.com', '*.example.com'));
        $this->assertFalse($validator->matchesWildcard('example.com', '*.sub.example.com'));
        $this->assertFalse($validator->matchesWildcard('other.com', '*.example.com'));

        // 多级通配符应该不匹配
        $this->assertFalse($validator->matchesWildcard('deep.sub.example.com', '*.example.com'));
    }
    
    public function testSignatureVerification(): void
    {
        $validator = new CertificateValidator([
            'allow_self_signed' => true,
        ]);

        $data = 'test data to sign';
        $signature = $validator->signData($data, $this->testPrivateKeyPem);

        $this->assertNotEmpty($signature);

        $verified = $validator->verifySignature($data, $signature, $this->testCertPem);
        $this->assertTrue($verified);
    }
    
    public function testInvalidSignatureVerification(): void
    {
        $validator = new CertificateValidator([
            'allow_self_signed' => true,
        ]);

        $data = 'test data';
        $invalidSignature = 'invalid signature';

        $verified = $validator->verifySignature($data, $invalidSignature, $this->testCertPem);
        $this->assertFalse($verified);
    }
    
    public function testTranscriptSignature(): void
    {
        $validator = new CertificateValidator([
            'allow_self_signed' => true,
        ]);

        // 设置服务器证书
        $validator->setServerCertificate($this->testCertPem, $this->testPrivateKeyPem);

        $transcriptHash = hash('sha256', 'test transcript', true);
        $signature = $validator->signTranscript($transcriptHash);

        $this->assertNotEmpty($signature);

        $verified = $validator->verifyTranscriptSignature($transcriptHash, $signature);
        $this->assertTrue($verified);
    }
    
    public function testCertificateInfo(): void
    {
        $info = $this->validator->getCertificateInfo($this->testCertPem);

        $this->assertArrayHasKey('subject', $info);
        $this->assertArrayHasKey('issuer', $info);
        $this->assertArrayHasKey('valid_from', $info);
        $this->assertArrayHasKey('valid_to', $info);
        $this->assertArrayHasKey('serial_number', $info);
    }
    
    public function testLoadSystemCACertificates(): void
    {
        $caPath = $this->validator->loadSystemCACertificates();

        // 应该返回一个有效的 CA 文件路径或空字符串
        if (!empty($caPath)) {
            $this->assertFileExists($caPath);
        }
    }
    
    public function testCertificateFingerprint(): void
    {
        $fingerprint = $this->validator->getCertificateFingerprint($this->testCertPem);

        $this->assertNotEmpty($fingerprint);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $fingerprint); // SHA256 hex
    }
    
    public function testCertificateChainOrder(): void
    {
        // 测试证书链的正确顺序
        $certificates = [$this->testCertPem]; // 单个证书

        $result = $this->validator->validateCertificateChain($certificates);
        $this->assertTrue($result);
    }
    
    public function testPeerValidationDisabled(): void
    {
        $validator = new CertificateValidator([
            'verify_peer' => false,
        ]);

        // 任何证书都应该通过验证
        $result = $validator->validateCertificate(['invalid cert']);
        $this->assertTrue($result);
    }
    
    public function testCertificateRevocation(): void
    {
        // 注意：真实的 CRL 检查需要网络访问，这里只测试接口
        $validator = new CertificateValidator([
            'check_revocation' => false, // 禁用撤销检查
            'allow_self_signed' => true, // 允许自签名证书用于测试
        ]);

        $certificates = [$this->testCertPem];
        $result = $validator->validateCertificate($certificates);

        // 禁用撤销检查时，有效证书应该通过
        $this->assertTrue($result);
    }
    
    public function testMultipleCertificatesInChain(): void
    {
        $validator = new CertificateValidator([
            'allow_self_signed' => true,
        ]);

        // 测试多个证书的情况（这里重复使用同一个证书作为示例）
        $certificates = [$this->testCertPem, $this->testCertPem];

        $result = $validator->validateCertificateChain($certificates);

        // 这种情况下应该失败，因为同一个证书重复了
        $this->assertFalse($result);
    }
    
    protected function setUp(): void
    {
        $this->validator = new CertificateValidator();

        // 创建测试证书和私钥
        $this->createTestCertificate();
    }
    
    /**
     * 创建测试用的自签名证书
     */
    private function createTestCertificate(): void
    {
        // 生成私钥
        $privateKey = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        
        // 创建证书请求
        $dn = [
            'C' => 'US',
            'ST' => 'Test State',
            'L' => 'Test City',
            'O' => 'Test Organization',
            'OU' => 'Test Unit',
            'CN' => 'test.example.com',
        ];
        
        $csr = openssl_csr_new($dn, $privateKey, [
            'digest_alg' => 'sha256',
            'x509_extensions' => 'v3_req',
        ]);
        
        // 创建自签名证书
        $cert = openssl_csr_sign($csr, null, $privateKey, 365, [
            'digest_alg' => 'sha256',
        ]);
        
        // 导出 PEM 格式
        openssl_x509_export($cert, $this->testCertPem);
        openssl_pkey_export($privateKey, $this->testPrivateKeyPem);
        
        // PHP 8+ 不需要手动释放资源，资源会自动释放
    }
}