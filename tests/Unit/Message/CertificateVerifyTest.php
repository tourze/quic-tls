<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Unit\Message;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Message\CertificateVerify;

class CertificateVerifyTest extends TestCase
{
    public function test_constructor_withDefaults(): void
    {
        $certificateVerify = new CertificateVerify();
        $this->assertEquals('', $certificateVerify->getSignature());
        $this->assertEquals(0x0403, $certificateVerify->getSignatureAlgorithm());
    }

    public function test_constructor_withSignature(): void
    {
        $signature = 'test-signature';
        $certificateVerify = new CertificateVerify($signature);
        $this->assertEquals($signature, $certificateVerify->getSignature());
        $this->assertEquals(0x0403, $certificateVerify->getSignatureAlgorithm());
    }

    public function test_constructor_withSignatureAndAlgorithm(): void
    {
        $signature = 'test-signature';
        $algorithm = 0x0503;
        $certificateVerify = new CertificateVerify($signature, $algorithm);
        $this->assertEquals($signature, $certificateVerify->getSignature());
        $this->assertEquals($algorithm, $certificateVerify->getSignatureAlgorithm());
    }

    public function test_setSignature(): void
    {
        $certificateVerify = new CertificateVerify();
        $signature = 'new-signature';
        $certificateVerify->setSignature($signature);
        $this->assertEquals($signature, $certificateVerify->getSignature());
    }

    public function test_setSignatureAlgorithm(): void
    {
        $certificateVerify = new CertificateVerify();
        $algorithm = 0x0603;
        $certificateVerify->setSignatureAlgorithm($algorithm);
        $this->assertEquals($algorithm, $certificateVerify->getSignatureAlgorithm());
    }

    public function test_encode_withEmptySignature(): void
    {
        $certificateVerify = new CertificateVerify();
        $encoded = $certificateVerify->encode();
        $this->assertNotEmpty($encoded);
        // 应该包含算法(2字节) + 签名长度(2字节) = 4字节
        $this->assertEquals(4, strlen($encoded));
    }

    public function test_encode_withSignature(): void
    {
        $signature = 'test-signature';
        $certificateVerify = new CertificateVerify($signature);
        $encoded = $certificateVerify->encode();
        $this->assertNotEmpty($encoded);
        // 应该包含算法(2字节) + 签名长度(2字节) + 签名内容
        $this->assertEquals(4 + strlen($signature), strlen($encoded));
    }

    public function test_encodeAndDecode_roundTrip(): void
    {
        $originalSignature = 'test-signature-data';
        $originalAlgorithm = 0x0503;
        
        $certificateVerify = new CertificateVerify($originalSignature, $originalAlgorithm);
        $encoded = $certificateVerify->encode();
        $decoded = CertificateVerify::decode($encoded);
        
        $this->assertEquals($originalSignature, $decoded->getSignature());
        $this->assertEquals($originalAlgorithm, $decoded->getSignatureAlgorithm());
    }

    public function test_decode_withBinaryData(): void
    {
        $algorithm = 0x0403;
        $signature = 'binary-signature-data';
        
        $data = pack('n', $algorithm); // 算法
        $data .= pack('n', strlen($signature)); // 签名长度
        $data .= $signature; // 签名内容
        
        $decoded = CertificateVerify::decode($data);
        $this->assertEquals($signature, $decoded->getSignature());
        $this->assertEquals($algorithm, $decoded->getSignatureAlgorithm());
    }

    public function test_supportedAlgorithms(): void
    {
        $algorithms = [
            0x0403, // ecdsa_secp256r1_sha256
            0x0503, // ecdsa_secp384r1_sha384
            0x0603, // ecdsa_secp521r1_sha512
            0x0804, // rsa_pss_rsae_sha256
            0x0805, // rsa_pss_rsae_sha384
            0x0806, // rsa_pss_rsae_sha512
        ];
        
        foreach ($algorithms as $algorithm) {
            $certificateVerify = new CertificateVerify('test-sig', $algorithm);
            $this->assertEquals($algorithm, $certificateVerify->getSignatureAlgorithm());
        }
    }
}