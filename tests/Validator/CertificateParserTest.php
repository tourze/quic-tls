<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Exception\InvalidCertificateException;
use Tourze\QUIC\TLS\Validator\CertificateParser;

/**
 * @internal
 */
#[CoversClass(CertificateParser::class)]
final class CertificateParserTest extends TestCase
{
    private CertificateParser $parser;

    private string $testCert = '';

    protected function setUp(): void
    {
        parent::setUp();

        $this->parser = new CertificateParser();
        $this->createTestCertificate();
    }

    public function testCheckCertificateValidity(): void
    {
        $validCertInfo = [
            'validFrom_time_t' => time() - 3600,
            'validTo_time_t' => time() + 3600,
        ];

        $result = $this->parser->checkCertificateValidity($validCertInfo);
        $this->assertTrue($result);
    }

    public function testCheckExpiredCertificate(): void
    {
        $expiredCertInfo = [
            'validFrom_time_t' => time() - 7200,
            'validTo_time_t' => time() - 3600,
        ];

        $result = $this->parser->checkCertificateValidity($expiredCertInfo);
        $this->assertFalse($result);
    }

    public function testCheckDuplicateCertificates(): void
    {
        $certificates = [$this->testCert, $this->testCert];

        $result = $this->parser->checkDuplicateCertificates($certificates);
        $this->assertTrue($result); // 应该发现重复
    }

    public function testCheckNoDuplicateCertificates(): void
    {
        $certificates = [$this->testCert];

        $result = $this->parser->checkDuplicateCertificates($certificates);
        $this->assertFalse($result); // 应该没有重复
    }

    public function testValidateAllCertificatesDates(): void
    {
        $certificates = [$this->testCert];

        $result = $this->parser->validateAllCertificatesDates($certificates);
        $this->assertTrue($result);
    }

    public function testGetCertificateInfo(): void
    {
        $info = $this->parser->getCertificateInfo($this->testCert);

        $this->assertArrayHasKey('subject', $info);
    }

    public function testGetCertificateInfoWithInvalidCertificate(): void
    {
        $this->expectException(InvalidCertificateException::class);

        $this->parser->getCertificateInfo('invalid certificate');
    }

    public function testGetCertificateFingerprint(): void
    {
        $fingerprint = $this->parser->getCertificateFingerprint($this->testCert);

        $this->assertEquals(64, strlen($fingerprint)); // SHA256 fingerprint length
    }

    private function createTestCertificate(): void
    {
        // 生成自签名证书用于测试
        $privateKey = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);

        if (false === $privateKey) {
            self::fail('Failed to create private key');
        }

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
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if (false === $csr || true === $csr) {
            self::fail('Failed to create certificate request');
        }

        $cert = openssl_csr_sign($csr, null, $privateKey, 365, [
            'digest_alg' => 'sha256',
        ]);

        if (false === $cert) {
            self::fail('Failed to create certificate');
        }

        if (!openssl_x509_export($cert, $this->testCert)) {
            self::fail('Failed to export certificate');
        }
    }
}
