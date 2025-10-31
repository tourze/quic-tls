<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Validator;

use Tourze\QUIC\TLS\Exception\InvalidCertificateException;

/**
 * 证书解析器
 *
 * 专门负责证书解析和信息提取
 */
class CertificateParser
{
    /**
     * 检查证书有效期
     *
     * @param array<string, mixed> $certInfo
     */
    public function checkCertificateValidity(array $certInfo): bool
    {
        $now = time();

        if (isset($certInfo['validTo_time_t']) && $certInfo['validTo_time_t'] < $now) {
            return false;
        }

        if (isset($certInfo['validFrom_time_t']) && $certInfo['validFrom_time_t'] > $now) {
            return false;
        }

        return true;
    }

    /**
     * 检查证书链中是否有重复证书
     *
     * @param array<int, string> $certificateChain
     */
    public function checkDuplicateCertificates(array $certificateChain): bool
    {
        $fingerprints = [];
        foreach ($certificateChain as $cert) {
            $fingerprint = openssl_x509_fingerprint($cert, 'sha256');
            if (false === $fingerprint) {
                return true; // 如果无法获取指纹，认为有问题
            }
            if (in_array($fingerprint, $fingerprints, true)) {
                return true; // 发现重复
            }
            $fingerprints[] = $fingerprint;
        }

        return false; // 没有重复
    }

    /**
     * 验证证书链中所有证书的有效期
     *
     * @param array<int, string> $certificateChain
     */
    public function validateAllCertificatesDates(array $certificateChain): bool
    {
        foreach ($certificateChain as $cert) {
            $certInfo = openssl_x509_parse($cert);
            if (false === $certInfo || !$this->checkCertificateValidity($certInfo)) {
                return false;
            }
        }

        return true;
    }

    /**
     * 获取证书信息
     *
     * @return array<string, mixed>
     */
    public function getCertificateInfo(string $certificate): array
    {
        $info = openssl_x509_parse($certificate);
        if (false === $info) {
            throw new InvalidCertificateException('无法解析证书');
        }

        // 添加额外的字段以满足测试需求
        if (isset($info['validFrom_time_t'])) {
            $info['valid_from'] = date('Y-m-d H:i:s', $info['validFrom_time_t']);
        }
        if (isset($info['validTo_time_t'])) {
            $info['valid_to'] = date('Y-m-d H:i:s', $info['validTo_time_t']);
        }
        if (isset($info['serialNumber'])) {
            $info['serial_number'] = $info['serialNumber'];
        }

        return $info;
    }

    /**
     * 获取证书指纹
     */
    public function getCertificateFingerprint(string $certificate): string
    {
        $x509 = openssl_x509_read($certificate);
        if (false === $x509) {
            throw new InvalidCertificateException('无法解析证书');
        }

        openssl_x509_export($x509, $pem);

        return hash('sha256', $pem);
    }
}
