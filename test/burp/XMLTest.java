package burp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

public class XMLTest {
    @Test
    void testTransformer() {
        String originalSamlRequest = "<samlp:AuthnRequest " +
                "ID=\"id\" " +
                "Version=\"2.0\" " +
                "IssueInstant=\"2025-09-09T09:50:51.133TZ\" " +
                "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" " +
                "AssertionConsumerServiceURL=\"https://example.com/saml\" " +
                "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
                "https://example.com" +
                "</saml:Issuer>\n" +
                "</samlp:AuthnRequest>";
        Optional<XMLUtilities.SAMLDocument> parsedDocument = XMLUtilities.SAMLDocument.parse(originalSamlRequest);
        assertTrue(parsedDocument.isPresent());
        XMLUtilities.SAMLDocument samlDocument = parsedDocument.get();
        samlDocument.setCompressed(true);
        samlDocument.setBase64Encoded(true);
        String transformedXml = samlDocument.transformDocument();
        String encodedResult = samlDocument.encode(transformedXml);
        assertNotNull(encodedResult);
        Optional<XMLUtilities.SAMLDocument> roundTripDocument = XMLUtilities.SAMLDocument.parse(encodedResult);
        assertTrue(roundTripDocument.isPresent());
    }

    @Test
    void testEmptyString() {
        Optional<byte[]> decompressed = XMLUtilities.tryDecompress(new byte[]{});
        assertFalse(decompressed.isPresent());
    }

    @Test
    void testEmptyInput() {
        Optional<XMLUtilities.SAMLDocument> doc = XMLUtilities.SAMLDocument.parse("");
        assertFalse(doc.isPresent());
    }

    @Test
    void testInvalidXML() {
        Optional<XMLUtilities.SAMLDocument> doc = XMLUtilities.SAMLDocument.parse("NOTXML");
        assertFalse(doc.isPresent());
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void testDecompressDeflateWithInvalidInput() {

        byte[] randomBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
        Optional<byte[]> result = XMLUtilities.tryDecompress(randomBytes);
        assertFalse(result.isPresent());

        byte[] truncatedDeflate = new byte[]{0x78, (byte) 0x9c};
        Optional<byte[]> truncatedResult = XMLUtilities.tryDecompress(truncatedDeflate);
        assertFalse(truncatedResult.isPresent());

        byte[] malformedData = new byte[]{0x78, (byte) 0x9c, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        Optional<byte[]> malformedResult = XMLUtilities.tryDecompress(malformedData);
        assertFalse(malformedResult.isPresent());

    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void testCompressDeflateWithInvalidInput() {

        byte[] emptyInput = new byte[0];
        Optional<byte[]> result = XMLUtilities.tryCompress(emptyInput);
        assertTrue(result.isPresent());

        byte[] randomBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
        Optional<byte[]> randomResult = XMLUtilities.tryCompress(randomBytes);
        assertTrue(randomResult.isPresent());

    }

}
