<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Validator\CALoader;

/**
 * @internal
 */
#[CoversClass(CALoader::class)]
final class CALoaderTest extends TestCase
{
    private CALoader $caLoader;

    protected function setUp(): void
    {
        parent::setUp();

        $this->caLoader = new CALoader();
    }

    public function testAddTrustedCA(): void
    {
        $caCert = '-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----';

        $this->caLoader->addTrustedCA($caCert);
        $trustedCAs = $this->caLoader->getTrustedCAs();

        $this->assertContains($caCert, $trustedCAs);
    }

    public function testGetSystemCACertificatePath(): void
    {
        $path = $this->caLoader->getSystemCACertificatePath();

        // 路径应该不为null（可能为空字符串）
        $this->assertNotNull($path);
    }

    public function testLoadSystemCAs(): void
    {
        $initialCount = count($this->caLoader->getTrustedCAs());

        $this->caLoader->loadSystemCAs();

        // 系统CA数量应该大于等于初始数量
        $this->assertGreaterThanOrEqual($initialCount, count($this->caLoader->getTrustedCAs()));
    }

    public function testGetTrustedCAsInitiallyEmpty(): void
    {
        $trustedCAs = $this->caLoader->getTrustedCAs();

        $this->assertEmpty($trustedCAs);
    }
}
