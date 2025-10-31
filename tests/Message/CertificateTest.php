<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Message;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Message\Certificate;

/**
 * @internal
 */
#[CoversClass(Certificate::class)]
final class CertificateTest extends TestCase
{
    public function testConstructorWithoutCertificates(): void
    {
        $certificate = new Certificate();
        $this->assertInstanceOf(Certificate::class, $certificate);
        $this->assertEmpty($certificate->getCertificateChain());
    }

    public function testConstructorWithStringCertificate(): void
    {
        $certData = 'test-certificate-data';
        $certificate = new Certificate($certData);
        $this->assertEquals([$certData], $certificate->getCertificateChain());
    }

    public function testConstructorWithArrayCertificates(): void
    {
        $certificates = ['cert1', 'cert2', 'cert3'];
        $certificate = new Certificate($certificates);
        $this->assertEquals($certificates, $certificate->getCertificateChain());
    }

    public function testSetCertificateChain(): void
    {
        $certificate = new Certificate();
        $certificates = ['cert1', 'cert2'];
        $certificate->setCertificateChain($certificates);
        $this->assertEquals($certificates, $certificate->getCertificateChain());
    }

    public function testAddCertificate(): void
    {
        $certificate = new Certificate(['cert1']);
        $certificate->addCertificate('cert2');
        $this->assertEquals(['cert1', 'cert2'], $certificate->getCertificateChain());
    }

    public function testGetLeafCertificate(): void
    {
        $certificate = new Certificate();
        $this->assertNull($certificate->getLeafCertificate());

        $certificate->addCertificate('leaf-cert');
        $certificate->addCertificate('intermediate-cert');
        $this->assertEquals('leaf-cert', $certificate->getLeafCertificate());
    }

    public function testCertificateRequestContext(): void
    {
        $certificate = new Certificate();
        $this->assertEquals('', $certificate->getCertificateRequestContext());

        $context = 'test-context';
        $certificate->setCertificateRequestContext($context);
        $this->assertEquals($context, $certificate->getCertificateRequestContext());
    }

    public function testSetCertificates(): void
    {
        $certificate = new Certificate();
        $certificates = ['cert1', 'cert2'];
        $certificate->setCertificates($certificates);
        $this->assertEquals($certificates, $certificate->getCertificateChain());
    }

    public function testEncodeEmptyCertificate(): void
    {
        $certificate = new Certificate();
        $encoded = $certificate->encode();
        $this->assertNotEmpty($encoded);
    }

    public function testEncodeWithCertificates(): void
    {
        $certificate = new Certificate(['test-cert']);
        $encoded = $certificate->encode();
        $this->assertNotEmpty($encoded);
    }

    public function testEncodeAndDecodeRoundTrip(): void
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

    public function testDecodeWithEmptyData(): void
    {
        $data = "\x00\x00\x00\x00"; // empty context, empty certificate list
        $certificate = Certificate::decode($data);
        $this->assertEquals('', $certificate->getCertificateRequestContext());
        $this->assertEmpty($certificate->getCertificateChain());
    }
}
