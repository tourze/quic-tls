<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\TLS;

use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Message\Certificate;
use Tourze\QUIC\TLS\Message\ClientHello;
use Tourze\QUIC\TLS\Message\Finished;
use Tourze\QUIC\TLS\Message\ServerHello;
use Tourze\QUIC\TLS\TLS\MessageHandler;

class MessageHandlerTest extends TestCase
{
    private MessageHandler $messageHandler;
    
    public function test_constructor_initializesCorrectly(): void
    {
        $this->assertInstanceOf(MessageHandler::class, $this->messageHandler);
    }
    
    public function test_parseMessage_withClientHello_parsesCorrectly(): void
    {
        $clientHello = new ClientHello();
        $clientHello->setRandom(random_bytes(32));
        $clientHello->setCipherSuites(['TLS_AES_128_GCM_SHA256']);
        $clientHello->setExtensions([]);

        $encodedMessage = $clientHello->encode();
        $messageData = pack('C', 1) . pack('N', strlen($encodedMessage)) . $encodedMessage; // ClientHello type

        $parsed = $this->messageHandler->parseMessage($messageData);
        $this->assertArrayHasKey('type', $parsed);
        $this->assertArrayHasKey('length', $parsed);
        $this->assertArrayHasKey('data', $parsed);
        $this->assertEquals(1, $parsed['type']); // CLIENT_HELLO
    }
    
    public function test_parseMessage_withServerHello_parsesCorrectly(): void
    {
        $serverHello = new ServerHello();
        $serverHello->setRandom(random_bytes(32));
        $serverHello->setCipherSuite(0x1301); // TLS_AES_128_GCM_SHA256
        $serverHello->setExtensions([]);

        $encodedMessage = $serverHello->encode();
        $messageData = pack('C', 2) . pack('N', strlen($encodedMessage)) . $encodedMessage; // ServerHello type

        $parsed = $this->messageHandler->parseMessage($messageData);
        $this->assertArrayHasKey('type', $parsed);
        $this->assertEquals(2, $parsed['type']); // SERVER_HELLO
    }
    
    public function test_parseMessage_withCertificate_parsesCorrectly(): void
    {
        $certificate = new Certificate();
        $certificate->setCertificates(['test certificate']);

        $encodedMessage = $certificate->encode();
        $messageData = pack('C', 11) . pack('N', strlen($encodedMessage)) . $encodedMessage; // Certificate type

        $parsed = $this->messageHandler->parseMessage($messageData);
        $this->assertEquals(11, $parsed['type']); // CERTIFICATE
    }
    
    public function test_parseMessage_withFinished_parsesCorrectly(): void
    {
        $finished = new Finished();
        $finished->setVerifyData(random_bytes(32));

        $encodedMessage = $finished->encode();
        $messageData = pack('C', 20) . pack('N', strlen($encodedMessage)) . $encodedMessage; // Finished type

        $parsed = $this->messageHandler->parseMessage($messageData);
        $this->assertEquals(20, $parsed['type']); // FINISHED
    }
    
    public function test_parseMessage_withInvalidMessage_throwsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('消息数据不完整');

        $invalidMessage = 'invalid';
        $this->messageHandler->parseMessage($invalidMessage);
    }
    
    public function test_parseMessage_withEmptyMessage_throwsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('消息数据不完整');

        $this->messageHandler->parseMessage('');
    }
    
    public function test_formatMessage_withClientHello_formatsCorrectly(): void
    {
        $clientHello = new ClientHello();
        $clientHello->setRandom(random_bytes(32));
        $clientHello->setCipherSuites(['TLS_AES_128_GCM_SHA256']);
        $clientHello->setExtensions([]);

        $formatted = $this->messageHandler->formatMessage($clientHello); // CLIENT_HELLO
        $this->assertArrayHasKey('type', $formatted);
        $this->assertArrayHasKey('data', $formatted);
        $this->assertEquals('ClientHello', $formatted['type']);
    }
    
    public function test_formatMessage_withServerHello_formatsCorrectly(): void
    {
        $serverHello = new ServerHello();
        $serverHello->setRandom(random_bytes(32));
        $serverHello->setCipherSuite(0x1301); // TLS_AES_128_GCM_SHA256
        $serverHello->setExtensions([]);

        $formatted = $this->messageHandler->formatMessage($serverHello); // SERVER_HELLO
        $this->assertArrayHasKey('type', $formatted);
        $this->assertEquals('ServerHello', $formatted['type']);
    }
    
    public function test_validateMessage_withValidMessage_returnsTrue(): void
    {
        $clientHello = new ClientHello();
        $clientHello->setRandom(random_bytes(32));
        $clientHello->setCipherSuites(['TLS_AES_128_GCM_SHA256']);
        $clientHello->setExtensions([]);

        $messageData = pack('C', 1) . substr(pack('N', strlen($clientHello->encode())), 1) . $clientHello->encode();

        $isValid = $this->messageHandler->validateMessage(1, $messageData);

        $this->assertTrue($isValid);
    }
    
    public function test_validateMessage_withInvalidType_returnsFalse(): void
    {
        $messageData = pack('C', 255) . pack('N', 10) . 'test data';

        $isValid = $this->messageHandler->validateMessage(1, $messageData); // 期望类型1，但实际是255

        $this->assertFalse($isValid);
    }
    
    public function test_validateMessage_withInconsistentLength_returnsFalse(): void
    {
        // 创建长度不一致的消息：声明100字节但只有5字节数据
        $messageData = pack('C', 1) . substr(pack('N', 100), 1) . 'short';

        $isValid = $this->messageHandler->validateMessage(1, $messageData);

        $this->assertFalse($isValid);
    }
    
    public function test_createAlert_createsAlertMessage(): void
    {
        $alertLevel = 2; // fatal
        $alertDescription = 10; // unexpected_message

        $alert = $this->messageHandler->createAlert($alertLevel, $alertDescription);
        $this->assertNotEmpty($alert);
    }
    
    public function test_parseAlert_parsesAlertCorrectly(): void
    {
        $alertData = pack('CC', 2, 10); // fatal, unexpected_message

        $parsed = $this->messageHandler->parseAlert($alertData);
        $this->assertArrayHasKey('level', $parsed);
        $this->assertArrayHasKey('description', $parsed);
        $this->assertEquals(2, $parsed['level']);
        $this->assertEquals(10, $parsed['description']);
    }
    
    public function test_parseAlert_withInvalidData_throwsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Alert 数据不完整');

        $invalidAlert = pack('C', 2); // 只有级别，缺少描述
        $this->messageHandler->parseAlert($invalidAlert);
    }
    
    public function test_wrapRecord_wrapsMessageInRecord(): void
    {
        $message = 'test message';
        $contentType = 22; // handshake

        $record = $this->messageHandler->wrapRecord($contentType, $message);
        $this->assertGreaterThan(strlen($message), strlen($record)); // 包含记录头
    }
    
    public function test_unwrapRecord_unwrapsRecordCorrectly(): void
    {
        $message = 'test message';
        $contentType = 22; // handshake

        // 先包装
        $record = $this->messageHandler->wrapRecord($contentType, $message);

        // 再解包
        $unwrapped = $this->messageHandler->unwrapRecord($record);
        $this->assertArrayHasKey('content_type', $unwrapped);
        $this->assertArrayHasKey('version', $unwrapped);
        $this->assertArrayHasKey('length', $unwrapped);
        $this->assertArrayHasKey('data', $unwrapped);
        $this->assertEquals($contentType, $unwrapped['content_type']);
        $this->assertEquals($message, $unwrapped['data']);
    }
    
    public function test_unwrapRecord_withInvalidRecord_throwsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('记录数据不完整');

        $invalidRecord = 'invalid';
        $this->messageHandler->unwrapRecord($invalidRecord);
    }
    
    public function test_getMessageTypeName_returnsCorrectName(): void
    {
        $this->assertEquals('CLIENT_HELLO', $this->messageHandler->getMessageTypeName(1));
        $this->assertEquals('SERVER_HELLO', $this->messageHandler->getMessageTypeName(2));
        $this->assertEquals('CERTIFICATE', $this->messageHandler->getMessageTypeName(11));
        $this->assertEquals('FINISHED', $this->messageHandler->getMessageTypeName(20));
        $this->assertEquals('UNKNOWN (255)', $this->messageHandler->getMessageTypeName(255));
    }
    
    public function test_updateTranscript_updatesCorrectly(): void
    {
        $message = 'test message for transcript';

        $this->messageHandler->updateTranscript($message);

        $transcript = $this->messageHandler->getTranscript();
        $this->assertStringContainsString($message, $transcript);
    }
    
    public function test_getTranscript_returnsTranscript(): void
    {
        $message1 = 'first message';
        $message2 = 'second message';

        $this->messageHandler->updateTranscript($message1);
        $this->messageHandler->updateTranscript($message2);

        $transcript = $this->messageHandler->getTranscript();
        $this->assertStringContainsString($message1, $transcript);
        $this->assertStringContainsString($message2, $transcript);
    }
    
    public function test_clearTranscript_clearsTranscript(): void
    {
        $this->messageHandler->updateTranscript('test message');
        $this->messageHandler->clearTranscript();

        $transcript = $this->messageHandler->getTranscript();
        $this->assertEmpty($transcript);
    }
    
    public function test_validateExtensions_withValidExtensions_returnsTrue(): void
    {
        $extensions = [
            0x002b => "\x03\x04", // supported_versions extension data
            0x0000 => "example.com", // server_name extension data
        ];

        $isValid = $this->messageHandler->validateExtensions($extensions);
        $this->assertTrue($isValid);
    }
    
    public function test_validateExtensions_withInvalidExtensions_returnsFalse(): void
    {
        $extensions = [
            'invalid_key' => 'value', // 字符串键是无效的
            0x000a => 123, // 非字符串值是无效的
        ];

        $isValid = $this->messageHandler->validateExtensions($extensions);
        $this->assertFalse($isValid);
    }
    
    protected function setUp(): void
    {
        $this->messageHandler = new MessageHandler();
    }
}