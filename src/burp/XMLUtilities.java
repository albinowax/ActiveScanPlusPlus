package burp;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Optional;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;


public class XMLUtilities {

    public static Optional<byte[]> tryBase64Decode(String input) {
        try {
            String urlDecoded = URLDecoder.decode(input, Charset.defaultCharset());
            byte[] base64Decoded = Base64.getDecoder().decode(urlDecoded);
            return Optional.of(base64Decoded);
        } catch (Exception e) {
            try {
                byte[] base64Decoded = Base64.getDecoder().decode(input);
                return Optional.of(base64Decoded);
            } catch (Exception ex) {
                return Optional.empty();
            }
        }
    }

    public static Optional<byte[]> tryDecompress(byte[] input) {
        try {
            byte[] decompressed = decompressDeflate(input);
            return Optional.of(decompressed);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public static Optional<byte[]> tryCompress(byte[] input) {
        try {
            byte[] compressed = compressDeflate(input);
            return Optional.of(compressed);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static byte[] compressDeflate(byte[] input) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        try {
            deflater.setInput(input);
            deflater.finish();

            ByteArrayOutputStream baos = new ByteArrayOutputStream(Math.max(32, input.length / 2));
            byte[] buffer = new byte[8192];

            while (!deflater.finished()) {
                int written = deflater.deflate(buffer, 0, buffer.length, Deflater.NO_FLUSH);

                if (written > 0) {
                    baos.write(buffer, 0, written);
                    continue;
                }

                if (deflater.needsInput()) {
                    throw new IllegalStateException("Deflater needs more input after finish(); input likely incomplete.");
                }

                if (!deflater.finished()) {
                    throw new IllegalStateException("Deflater made no progress (possible invalid state).");
                }
            }

            return baos.toByteArray();
        } finally {
            deflater.end();
        }
    }

    private static byte[] decompressDeflate(byte[] input) throws DataFormatException {
        Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(input);

            ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length * 2);
            byte[] buffer = new byte[8192];

            while (!inflater.finished()) {
                int read = inflater.inflate(buffer);

                if (read > 0) {
                    baos.write(buffer, 0, read);
                    continue;
                }

                if (inflater.needsDictionary()) {
                    throw new DataFormatException("Preset dictionary required for this stream.");
                }
                if (inflater.needsInput()) {
                    throw new DataFormatException("Truncated deflate stream (needs more input).");
                }

                throw new DataFormatException("Inflater made no progress (corrupt or invalid stream).");
            }

            return baos.toByteArray();
        } finally {
            inflater.end();
        }
    }

    public static class SAMLDocument {
        private boolean isBase64Encoded;
        private boolean isCompressed;
        private Document document;

        public SAMLDocument(boolean isBase64Encoded, boolean isCompressed, Document document) {
            this.isBase64Encoded = isBase64Encoded;
            this.isCompressed = isCompressed;
            this.document = document;
        }

        public void setBase64Encoded(boolean base64Encoded) {
            isBase64Encoded = base64Encoded;
        }

        public void setCompressed(boolean compressed) {
            isCompressed = compressed;
        }

        public Document getDocument() {
            return document;
        }

        public SAMLDocument copy() throws ParserConfigurationException {
            Document copy = DocumentBuilderFactory.newInstance()
                    .newDocumentBuilder()
                    .newDocument();
            copy.appendChild(copy.importNode(document.getDocumentElement(), true));
            return new SAMLDocument(isBase64Encoded, isCompressed, copy);
        }

        public String transformDocument() {
            try {
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                StringWriter writer = new StringWriter();
                transformer.transform(new DOMSource(document), new StreamResult(writer));
                return writer.toString();
            } catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        }
        public static Pair<String, String> detectUnsafeDOCTYPE(XMLUtilities.SAMLDocument document) {
            if (document == null || document.getDocument().getDoctype() != null) {
                throw new IllegalArgumentException();
            }
            String str = "<!DOCTYPE root SYSTEM \"example.dtd\">" + document.transformDocument();
            return new ImmutablePair<>(document.encode(str), "");
        }

        public static Pair<String, String> detectUnsafeENTITIES(XMLUtilities.SAMLDocument document) {
            if (document == null || document.getDocument().getDoctype() != null) {
                throw new IllegalArgumentException();
            }
            try {
                XPathFactory xPathFactory = XPathFactory.newInstance();
                XPath xpath = xPathFactory.newXPath();
                XPathExpression expr = xpath.compile("//*[@ID]");

                Node node = (Node) expr.evaluate(document.getDocument(), XPathConstants.NODE);
                if (node != null && node.getAttributes() != null) {
                    Attr idAttr = (Attr) node.getAttributes().getNamedItem("ID");
                    if (idAttr != null) {
                        String uuid = idAttr.getValue();
                        idAttr.setValue("PLACEHOLDER_UUID");
                        String str = String.format("<!DOCTYPE foo [ <!ENTITY uuid SYSTEM \"%s\"> ]>", uuid);
                        str += document.transformDocument();
                        str = str.replace("PLACEHOLDER_UUID", "&uuid;");
                        return new ImmutablePair<>(document.encode(str), "");
                    }
                }
                throw new IllegalArgumentException();
            } catch (Exception e) {
                throw new IllegalArgumentException();
            }
        }

        public static Optional<SAMLDocument> parse(String xmlString) {
            try {
                boolean isB64 = false;
                boolean isDeflated = false;

                String processedData = xmlString;
                Optional<byte[]> optionalBytes = XMLUtilities.tryBase64Decode(processedData);

                if (optionalBytes.isPresent() && optionalBytes.get().length != 0) {
                    isB64 = true;
                    byte[] data = optionalBytes.get();
                    if (data[0] == '<') {
                        processedData = new String(data, Charset.defaultCharset());
                    } else {
                        Optional<byte[]> decompressed = XMLUtilities.tryDecompress(data);
                        if (decompressed.isPresent() && decompressed.get().length != 0) {
                            isDeflated = true;
                            processedData = new String(decompressed.get(), Charset.defaultCharset());
                        }
                    }
                }

                if (!processedData.startsWith("<")) throw new IllegalArgumentException();
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
                factory.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
                factory.setNamespaceAware(true);

                DocumentBuilder builder = factory.newDocumentBuilder();
                try (ByteArrayInputStream inputStream = new ByteArrayInputStream(processedData.getBytes(Charset.defaultCharset()))) {
                    Document document = builder.parse(inputStream);
                    return Optional.of(new SAMLDocument(isB64, isDeflated, document));
                }
            } catch (Exception e) {
                return Optional.empty();
            }
        }

        public String encode(String input) {
            byte[] result = input.getBytes(Charset.defaultCharset());
            if (isCompressed) {
                result = XMLUtilities.compressDeflate(result);
            }
            if (isBase64Encoded) {
                result = Base64.getEncoder().encode(result);
            }
            return new String(result, Charset.defaultCharset());
        }

    }
}
