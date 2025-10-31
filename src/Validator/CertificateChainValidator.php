<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Validator;

/**
 * 证书链验证器
 *
 * 专门负责证书链的验证逻辑
 */
class CertificateChainValidator
{
    /**
     * @param array<int, string> $trustedCAs
     */
    public function __construct(private readonly array $trustedCAs = [], private readonly bool $allowSelfSigned = false, private readonly int $verifyDepth = 7)
    {
    }

    /**
     * 验证证书链
     *
     * @param array<int, string> $certificateChain
     */
    public function validateChain(array $certificateChain): bool
    {
        $chainLength = count($certificateChain);

        if ($chainLength > $this->verifyDepth) {
            return false;
        }

        if (1 === $chainLength) {
            return $this->validateSingleCertificate($certificateChain[0]);
        }

        return $this->validateMultipleCertificates($certificateChain);
    }

    /**
     * 验证单个证书
     */
    private function validateSingleCertificate(string $cert): bool
    {
        $isSelfSigned = $this->verifySelfSignedCertificate($cert);

        if ($isSelfSigned) {
            return $this->allowSelfSigned;
        }

        return $this->verifyRootCertificate($cert);
    }

    /**
     * 验证多个证书
     *
     * @param array<int, string> $certificateChain
     */
    private function validateMultipleCertificates(array $certificateChain): bool
    {
        if (!$this->validateCertificateSignatures($certificateChain)) {
            return false;
        }

        $rootCert = $certificateChain[count($certificateChain) - 1];

        return $this->verifyRootCertificate($rootCert);
    }

    /**
     * 验证证书链中的签名关系
     *
     * @param array<int, string> $certificateChain
     */
    private function validateCertificateSignatures(array $certificateChain): bool
    {
        $chainLength = count($certificateChain);

        for ($i = 0; $i < $chainLength - 1; ++$i) {
            $currentCert = $certificateChain[$i];
            $issuerCert = $certificateChain[$i + 1];

            if (!$this->verifyCertificateSignature($currentCert, $issuerCert)) {
                return false;
            }
        }

        return true;
    }

    /**
     * 验证证书签名
     */
    private function verifyCertificateSignature(string $cert, string $issuerCert): bool
    {
        $pubKey = openssl_pkey_get_public($issuerCert);
        if (false === $pubKey) {
            return false;
        }

        $result = openssl_x509_verify($cert, $pubKey);

        return 1 === $result;
    }

    /**
     * 验证自签名证书
     */
    private function verifySelfSignedCertificate(string $cert): bool
    {
        $pubKey = openssl_pkey_get_public($cert);
        if (false === $pubKey) {
            return false;
        }

        return 1 === openssl_x509_verify($cert, $pubKey);
    }

    /**
     * 验证根证书
     */
    private function verifyRootCertificate(string $rootCert): bool
    {
        foreach ($this->trustedCAs as $trustedCA) {
            if ($this->compareCertificates($rootCert, $trustedCA)) {
                return true;
            }
        }

        return $this->verifySelfSignedCertificate($rootCert);
    }

    /**
     * 比较两个证书是否相同
     */
    private function compareCertificates(string $cert1, string $cert2): bool
    {
        $fingerprint1 = openssl_x509_fingerprint($cert1, 'sha256');
        $fingerprint2 = openssl_x509_fingerprint($cert2, 'sha256');

        return $fingerprint1 === $fingerprint2;
    }
}
