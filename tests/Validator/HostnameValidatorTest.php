<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Validator\HostnameValidator;

/**
 * @internal
 */
#[CoversClass(HostnameValidator::class)]
final class HostnameValidatorTest extends TestCase
{
    private HostnameValidator $validator;

    private string $testCert = '';

    protected function setUp(): void
    {
        parent::setUp();

        $this->validator = new HostnameValidator(true);
        $this->createTestCertificate();
    }

    public function testValidateHostnameWithMatchingCN(): void
    {
        $result = $this->validator->validateHostname($this->testCert, 'test.example.com');

        $this->assertTrue($result);
    }

    public function testValidateHostnameWithNonMatchingCN(): void
    {
        $result = $this->validator->validateHostname($this->testCert, 'different.example.com');

        $this->assertFalse($result);
    }

    public function testValidateHostnameWithVerifyPeerNameDisabled(): void
    {
        $disabledValidator = new HostnameValidator(false);

        $result = $disabledValidator->validateHostname($this->testCert, 'any.hostname.com');

        $this->assertTrue($result); // 应该总是返回true，因为验证被禁用
    }

    public function testMatchesWildcard(): void
    {
        $result = $this->validator->matchesWildcard('test.example.com', '*.example.com');

        $this->assertTrue($result);
    }

    public function testMatchesWildcardNoMatch(): void
    {
        $result = $this->validator->matchesWildcard('test.different.com', '*.example.com');

        $this->assertFalse($result);
    }

    public function testMatchesExactHostname(): void
    {
        $result = $this->validator->matchesWildcard('test.example.com', 'test.example.com');

        $this->assertTrue($result);
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
