<?php

declare(strict_types=1);

namespace Tourze\QUIC\TLS\Tests\TLS;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\QUIC\TLS\Message\Certificate;
use Tourze\QUIC\TLS\Message\ClientHello;
use Tourze\QUIC\TLS\Message\EncryptedExtensions;
use Tourze\QUIC\TLS\Message\Finished;
use Tourze\QUIC\TLS\Message\ServerHello;
use Tourze\QUIC\TLS\TLS\MessageHandler;

/**
 * @internal
 */
#[CoversClass(MessageHandler::class)]
final class MessageHandlerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // 异常/消息测试不需要数据库设置
    }

    private MessageHandler $messageHandler;

    public function testConstructorInitializesCorrectly(): void
    {
        $this->assertInstanceOf(MessageHandler::class, $this->getMessageHandler());
    }

    public function testParseMessageWithClientHelloParsesCorrectly(): void
    {
        $clientHello = new ClientHello();
        $clientHello->setRandom(random_bytes(32));
        $clientHello->setCipherSuites([0x1301]); // TLS_AES_128_GCM_SHA256
        $clientHello->setExtensions([]);

        $encodedMessage = $clientHello->encode();
        $messageData = pack('C', 1) . pack('N', strlen($encodedMessage)) . $encodedMessage; // ClientHello type

        $parsed = $this->getMessageHandler()->parseMessage($messageData);
        $this->assertArrayHasKey('type', $parsed);
        $this->assertArrayHasKey('length', $parsed);
        $this->assertArrayHasKey('data', $parsed);
        $this->assertEquals(1, $parsed['type']); // CLIENT_HELLO
    }

    public function testParseMessageWithServerHelloParsesCorrectly(): void
    {
        $serverHello = new ServerHello();
        $serverHello->setRandom(random_bytes(32));
        $serverHello->setCipherSuite(0x1301); // TLS_AES_128_GCM_SHA256
        $serverHello->setExtensions([]);

        $encodedMessage = $serverHello->encode();
        $messageData = pack('C', 2) . pack('N', strlen($encodedMessage)) . $encodedMessage; // ServerHello type

        $parsed = $this->getMessageHandler()->parseMessage($messageData);
        $this->assertArrayHasKey('type', $parsed);
        $this->assertEquals(2, $parsed['type']); // SERVER_HELLO
    }

    public function testParseMessageWithCertificateParsesCorrectly(): void
    {
        $certificate = new Certificate();
        $certificate->setCertificates(['test certificate']);

        $encodedMessage = $certificate->encode();
        $messageData = pack('C', 11) . pack('N', strlen($encodedMessage)) . $encodedMessage; // Certificate type

        $parsed = $this->getMessageHandler()->parseMessage($messageData);
        $this->assertEquals(11, $parsed['type']); // CERTIFICATE
    }

    public function testParseMessageWithFinishedParsesCorrectly(): void
    {
        $verifyData = random_bytes(32);
        $finished = new Finished($verifyData);

        $encodedMessage = $finished->encode();
        $messageData = pack('C', 20) . pack('N', strlen($encodedMessage)) . $encodedMessage; // Finished type

        $parsed = $this->getMessageHandler()->parseMessage($messageData);
        $this->assertEquals(20, $parsed['type']); // FINISHED
    }

    public function testParseMessageWithInvalidMessageThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('消息数据不完整');

        $invalidMessage = 'invalid';
        $this->getMessageHandler()->parseMessage($invalidMessage);
    }

    public function testParseMessageWithEmptyMessageThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('消息数据不完整');

        $this->getMessageHandler()->parseMessage('');
    }

    public function testFormatMessageWithClientHelloFormatsCorrectly(): void
    {
        $clientHello = new ClientHello();
        $clientHello->setRandom(random_bytes(32));
        $clientHello->setCipherSuites([0x1301]); // TLS_AES_128_GCM_SHA256
        $clientHello->setExtensions([]);

        $formatted = $this->getMessageHandler()->formatMessage($clientHello); // CLIENT_HELLO
        $this->assertArrayHasKey('type', $formatted);
        $this->assertArrayHasKey('data', $formatted);
        $this->assertEquals('ClientHello', $formatted['type']);
    }

    public function testFormatMessageWithServerHelloFormatsCorrectly(): void
    {
        $serverHello = new ServerHello();
        $serverHello->setRandom(random_bytes(32));
        $serverHello->setCipherSuite(0x1301); // TLS_AES_128_GCM_SHA256
        $serverHello->setExtensions([]);

        $formatted = $this->getMessageHandler()->formatMessage($serverHello); // SERVER_HELLO
        $this->assertArrayHasKey('type', $formatted);
        $this->assertEquals('ServerHello', $formatted['type']);
    }

    public function testValidateMessageWithValidMessageReturnsTrue(): void
    {
        $clientHello = new ClientHello();
        $clientHello->setRandom(random_bytes(32));
        $clientHello->setCipherSuites([0x1301]); // TLS_AES_128_GCM_SHA256
        $clientHello->setExtensions([]);

        $messageData = pack('C', 1) . substr(pack('N', strlen($clientHello->encode())), 1) . $clientHello->encode();

        $isValid = $this->getMessageHandler()->validateMessage(1, $messageData);

        $this->assertTrue($isValid);
    }

    public function testValidateMessageWithInvalidTypeReturnsFalse(): void
    {
        $messageData = pack('C', 255) . pack('N', 10) . 'test data';

        $isValid = $this->getMessageHandler()->validateMessage(1, $messageData); // 期望类型1，但实际是255

        $this->assertFalse($isValid);
    }

    public function testValidateMessageWithInconsistentLengthReturnsFalse(): void
    {
        // 创建长度不一致的消息：声明100字节但只有5字节数据
        $messageData = pack('C', 1) . substr(pack('N', 100), 1) . 'short';

        $isValid = $this->getMessageHandler()->validateMessage(1, $messageData);

        $this->assertFalse($isValid);
    }

    public function testCreateAlertCreatesAlertMessage(): void
    {
        $alertLevel = 2; // fatal
        $alertDescription = 10; // unexpected_message

        $alert = $this->getMessageHandler()->createAlert($alertLevel, $alertDescription);
        $this->assertNotEmpty($alert);
    }

    public function testParseAlertParsesAlertCorrectly(): void
    {
        $alertData = pack('CC', 2, 10); // fatal, unexpected_message

        $parsed = $this->getMessageHandler()->parseAlert($alertData);
        $this->assertArrayHasKey('level', $parsed);
        $this->assertArrayHasKey('description', $parsed);
        $this->assertEquals(2, $parsed['level']);
        $this->assertEquals(10, $parsed['description']);
    }

    public function testParseAlertWithInvalidDataThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Alert 数据不完整');

        $invalidAlert = pack('C', 2); // 只有级别，缺少描述
        $this->getMessageHandler()->parseAlert($invalidAlert);
    }

    public function testWrapRecordWrapsMessageInRecord(): void
    {
        $message = 'test message';
        $contentType = 22; // handshake

        $record = $this->getMessageHandler()->wrapRecord($contentType, $message);
        $this->assertGreaterThan(strlen($message), strlen($record)); // 包含记录头
    }

    public function testUnwrapRecordUnwrapsRecordCorrectly(): void
    {
        $message = 'test message';
        $contentType = 22; // handshake

        // 先包装
        $record = $this->getMessageHandler()->wrapRecord($contentType, $message);

        // 再解包
        $unwrapped = $this->getMessageHandler()->unwrapRecord($record);
        $this->assertArrayHasKey('content_type', $unwrapped);
        $this->assertArrayHasKey('version', $unwrapped);
        $this->assertArrayHasKey('length', $unwrapped);
        $this->assertArrayHasKey('data', $unwrapped);
        $this->assertEquals($contentType, $unwrapped['content_type']);
        $this->assertEquals($message, $unwrapped['data']);
    }

    public function testUnwrapRecordWithInvalidRecordThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('记录数据不完整');

        $invalidRecord = 'invalid';
        $this->getMessageHandler()->unwrapRecord($invalidRecord);
    }

    public function testGetMessageTypeNameReturnsCorrectName(): void
    {
        $this->assertEquals('CLIENT_HELLO', $this->getMessageHandler()->getMessageTypeName(1));
        $this->assertEquals('SERVER_HELLO', $this->getMessageHandler()->getMessageTypeName(2));
        $this->assertEquals('CERTIFICATE', $this->getMessageHandler()->getMessageTypeName(11));
        $this->assertEquals('FINISHED', $this->getMessageHandler()->getMessageTypeName(20));
        $this->assertEquals('UNKNOWN (255)', $this->getMessageHandler()->getMessageTypeName(255));
    }

    public function testUpdateTranscriptUpdatesCorrectly(): void
    {
        $message = 'test message for transcript';

        $this->getMessageHandler()->updateTranscript($message);

        $transcript = $this->getMessageHandler()->getTranscript();
        $this->assertStringContainsString($message, $transcript);
    }

    public function testGetTranscriptReturnsTranscript(): void
    {
        $message1 = 'first message';
        $message2 = 'second message';

        $this->getMessageHandler()->updateTranscript($message1);
        $this->getMessageHandler()->updateTranscript($message2);

        $transcript = $this->getMessageHandler()->getTranscript();
        $this->assertStringContainsString($message1, $transcript);
        $this->assertStringContainsString($message2, $transcript);
    }

    public function testClearTranscriptClearsTranscript(): void
    {
        $this->getMessageHandler()->updateTranscript('test message');
        $this->getMessageHandler()->clearTranscript();

        $transcript = $this->getMessageHandler()->getTranscript();
        $this->assertEmpty($transcript);
    }

    public function testValidateExtensionsWithValidExtensionsReturnsTrue(): void
    {
        $extensions = [
            0x002B => "\x03\x04", // supported_versions extension data
            0x0000 => 'example.com', // server_name extension data
        ];

        $isValid = $this->getMessageHandler()->validateExtensions($extensions);
        $this->assertTrue($isValid);
    }

    public function testValidateExtensionsWithInvalidExtensionsReturnsFalse(): void
    {
        $extensions = [
            'invalid_key' => 'value', // 字符串键是无效的
            0x000A => 123, // 非字符串值是无效的
        ];

        $isValid = $this->getMessageHandler()->validateExtensions($extensions);
        $this->assertFalse($isValid);
    }

    public function testCreateAlertRecord(): void
    {
        $level = 2; // fatal
        $description = 40; // handshake_failure

        $alertRecord = $this->getMessageHandler()->createAlertRecord($level, $description);

        $this->assertNotEmpty($alertRecord);
        $this->assertIsString($alertRecord);
        $this->assertStringContainsString(chr($level), $alertRecord);
        $this->assertStringContainsString(chr($description), $alertRecord);
    }

    public function testCreateClientHandshakeSequence(): void
    {
        $clientHello = new ClientHello();
        $clientHello->setRandom(random_bytes(32));
        $clientHello->setCipherSuites([0x1301]); // TLS_AES_128_GCM_SHA256

        $sequence = $this->getMessageHandler()->createClientHandshakeSequence($clientHello);

        $this->assertIsArray($sequence);
        $this->assertNotEmpty($sequence);
        $this->assertArrayHasKey(0, $sequence);
    }

    public function testCreateHandshakeRecord(): void
    {
        $clientHello = new ClientHello();
        $clientHello->setRandom(random_bytes(32));
        $encodedMessage = $clientHello->encode();
        $messages = [$encodedMessage];

        $record = $this->getMessageHandler()->createHandshakeRecord($messages);

        $this->assertNotEmpty($record);
        $this->assertIsString($record);
    }

    public function testCreateRecord(): void
    {
        $type = 22; // handshake
        $data = 'test data';

        $record = $this->getMessageHandler()->createRecord($type, $data);

        $this->assertNotEmpty($record);
        $this->assertIsString($record);
        $this->assertGreaterThan(5, strlen($record)); // header + data
    }

    public function testCreateServerHandshakeSequence(): void
    {
        $clientHello = new ClientHello();
        $clientHello->setRandom(random_bytes(32));

        $serverHello = new ServerHello();
        $serverHello->setRandom(random_bytes(32));

        $certificate = new Certificate();

        $encryptedExtensions = new EncryptedExtensions();

        $sequence = $this->getMessageHandler()->createServerHandshakeSequence(
            $serverHello,
            $encryptedExtensions,
            $certificate
        );

        $this->assertIsArray($sequence);
        $this->assertNotEmpty($sequence);
    }

    public function testDecodeMessage(): void
    {
        $type = 1; // CLIENT_HELLO
        $data = 'invalid message data';

        // 测试错误处理
        $this->expectException(\Throwable::class);
        $this->getMessageHandler()->decodeMessage($type, $data);
    }

    public function testEncodeMessage(): void
    {
        $type = 1; // CLIENT_HELLO
        $payload = 'test payload';

        $encoded = $this->getMessageHandler()->encodeMessage($type, $payload);

        $this->assertNotEmpty($encoded);
        $this->assertIsString($encoded);
    }

    public function testFragmentMessage(): void
    {
        $message = str_repeat('a', 32768); // 32KB message
        $maxFragmentSize = 16384; // 16KB

        $fragments = $this->getMessageHandler()->fragmentMessage($message, $maxFragmentSize);

        $this->assertIsArray($fragments);
        $this->assertGreaterThan(1, count($fragments));
        $this->assertLessThanOrEqual($maxFragmentSize, strlen($fragments[0]));
    }

    public function testParseHandshakeData(): void
    {
        // 创建一个简单的握手记录用于测试
        $clientHello = new ClientHello();
        $clientHello->setRandom(random_bytes(32));
        $payload = $clientHello->encode();

        // 构造握手消息
        $messageType = 1; // CLIENT_HELLO
        $messageLength = strlen($payload);
        $handshakeMessage = chr($messageType) .
                           chr(($messageLength >> 16) & 0xFF) .
                           chr(($messageLength >> 8) & 0xFF) .
                           chr($messageLength & 0xFF) .
                           $payload;

        // 构造 TLS 记录
        $recordType = 22; // handshake
        $version = 0x0303; // TLS 1.2
        $recordLength = strlen($handshakeMessage);
        $record = chr($recordType) .
                 pack('n', $version) .
                 pack('n', $recordLength) .
                 $handshakeMessage;

        $messages = $this->getMessageHandler()->parseHandshakeData($record);

        $this->assertIsArray($messages);
        $this->assertNotEmpty($messages);
    }

    public function testReassembleFragments(): void
    {
        $fragment1 = 'Hello';
        $fragment2 = ' ';
        $fragment3 = 'World';
        $fragments = [$fragment1, $fragment2, $fragment3];

        $reassembled = $this->getMessageHandler()->reassembleFragments($fragments);

        $this->assertEquals('Hello World', $reassembled);
    }

    private function getMessageHandler(): MessageHandler
    {
        return $this->messageHandler ??= new MessageHandler();
    }
}
