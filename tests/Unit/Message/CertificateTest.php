<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Unit\Message;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Message\Certificate;

class CertificateTest extends TestCase
{
    public function test_constructor_withoutCertificates(): void
    {
        $certificate = new Certificate();
        $this->assertInstanceOf(Certificate::class, $certificate);
        $this->assertEmpty($certificate->getCertificateChain());
    }

    public function test_constructor_withStringCertificate(): void
    {
        $certData = 'test-certificate-data';
        $certificate = new Certificate($certData);
        $this->assertEquals([$certData], $certificate->getCertificateChain());
    }

    public function test_constructor_withArrayCertificates(): void
    {
        $certificates = ['cert1', 'cert2', 'cert3'];
        $certificate = new Certificate($certificates);
        $this->assertEquals($certificates, $certificate->getCertificateChain());
    }

    public function test_setCertificateChain(): void
    {
        $certificate = new Certificate();
        $certificates = ['cert1', 'cert2'];
        $certificate->setCertificateChain($certificates);
        $this->assertEquals($certificates, $certificate->getCertificateChain());
    }

    public function test_addCertificate(): void
    {
        $certificate = new Certificate(['cert1']);
        $certificate->addCertificate('cert2');
        $this->assertEquals(['cert1', 'cert2'], $certificate->getCertificateChain());
    }

    public function test_getLeafCertificate(): void
    {
        $certificate = new Certificate();
        $this->assertNull($certificate->getLeafCertificate());

        $certificate->addCertificate('leaf-cert');
        $certificate->addCertificate('intermediate-cert');
        $this->assertEquals('leaf-cert', $certificate->getLeafCertificate());
    }

    public function test_certificateRequestContext(): void
    {
        $certificate = new Certificate();
        $this->assertEquals('', $certificate->getCertificateRequestContext());

        $context = 'test-context';
        $certificate->setCertificateRequestContext($context);
        $this->assertEquals($context, $certificate->getCertificateRequestContext());
    }

    public function test_setCertificates(): void
    {
        $certificate = new Certificate();
        $certificates = ['cert1', 'cert2'];
        $certificate->setCertificates($certificates);
        $this->assertEquals($certificates, $certificate->getCertificateChain());
    }

    public function test_encode_emptyCertificate(): void
    {
        $certificate = new Certificate();
        $encoded = $certificate->encode();
        $this->assertNotEmpty($encoded);
    }

    public function test_encode_withCertificates(): void
    {
        $certificate = new Certificate(['test-cert']);
        $encoded = $certificate->encode();
        $this->assertNotEmpty($encoded);
    }

    public function test_encodeAndDecode_roundTrip(): void
    {
        $originalCertificates = ['cert1', 'cert2'];
        $originalContext = 'test-context';
        
        $certificate = new Certificate($originalCertificates);
        $certificate->setCertificateRequestContext($originalContext);
        
        $encoded = $certificate->encode();
        $decoded = Certificate::decode($encoded);
        
        $this->assertEquals($originalCertificates, $decoded->getCertificateChain());
        $this->assertEquals($originalContext, $decoded->getCertificateRequestContext());
    }

    public function test_decode_withEmptyData(): void
    {
        $data = "\x00\x00\x00\x00"; // empty context, empty certificate list
        $certificate = Certificate::decode($data);
        $this->assertEquals('', $certificate->getCertificateRequestContext());
        $this->assertEmpty($certificate->getCertificateChain());
    }
}