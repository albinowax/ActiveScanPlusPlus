package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
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
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import static burp.Utilities.helpers;

public class XMLScan extends ParamScan {
    private final Map<String, CheckDetails> checks;
    private final Set<AttributeType> ATTRIBUTES;
    private final int confirmCount;
    private boolean isCompressed;
    private boolean isBase64Encoded;


    public XMLScan(String name) {
        super(name);
        this.checks = new HashMap<>();
        this.checks.put("DOCTYPE", new CheckDetails(this::detectUnsafeDOCTYPE,
                List.of("https://portswigger.net/research/saml-roulette-the-hacker-always-wins")));
        this.checks.put("ENTITY", new CheckDetails(this::detectUnsafeENTITIES,
                List.of("https://portswigger.net/research/saml-roulette-the-hacker-always-wins")));
        this.checks.put("Unsigned XML", new CheckDetails(this::detectUnsignedDocument,
                List.of("https://portswigger.net/research/saml-roulette-the-hacker-always-wins")));
        this.confirmCount = 2;
        this.isCompressed = false;
        this.isBase64Encoded = false;
        this.ATTRIBUTES = new HashSet<>();
        this.ATTRIBUTES.addAll(Set.of(AttributeType.values()));
        this.ATTRIBUTES.removeAll(Set.of(
                AttributeType.BODY_CONTENT,
                AttributeType.WORD_COUNT,
                AttributeType.INITIAL_CONTENT,
                AttributeType.LINE_COUNT,
                AttributeType.LIMITED_BODY_CONTENT,
                AttributeType.CONTENT_LENGTH));
    }

    public static List<AttributeType> getUniqueAttributeTypes(List<Attribute> firstAttributes, List<Attribute> secondAttributes) {
        List<AttributeType> mismatchedTypes = new ArrayList<>();

        if (firstAttributes.size() != secondAttributes.size()) {
            return mismatchedTypes;
        }
        for (Attribute first : firstAttributes) {
            Optional<Attribute> second = secondAttributes.stream().filter(attribute -> attribute.type() == first.type()).findFirst();
            if (second.isPresent() && second.get().value() != first.value()) mismatchedTypes.add(first.type());
        }
        return mismatchedTypes;
    }

    private Pair<String, String> detectUnsafeDOCTYPE(Document document) {
        if (document == null || document.getDoctype() != null) {
            throw new IllegalArgumentException();
        }
        String str = "<!DOCTYPE root SYSTEM \"example.dtd\">" + transformDocument(document);
        return new ImmutablePair<>(compressIfNeeded(str), "");
    }

    private Pair<String, String> detectUnsafeENTITIES(Document document) {
        if (document == null || document.getDoctype() != null) {
            throw new IllegalArgumentException();
        }
        try {
            XPathFactory xPathFactory = XPathFactory.newInstance();
            XPath xpath = xPathFactory.newXPath();
            XPathExpression expr = xpath.compile("//*[@ID]");

            Node node = (Node) expr.evaluate(document, XPathConstants.NODE);
            if (node != null && node.getAttributes() != null) {
                Attr idAttr = (Attr) node.getAttributes().getNamedItem("ID");
                if (idAttr != null) {
                    String uuid = idAttr.getValue();
                    idAttr.setValue("PLACEHOLDER_UUID");
                    String str = String.format("<!DOCTYPE foo [ <!ENTITY uuid SYSTEM \"%s\"> ]>", uuid);
                    str += transformDocument(document);
                    str = str.replace("PLACEHOLDER_UUID", "&uuid;");
                    return new ImmutablePair<>(compressIfNeeded(str), "");
                }
            }
            throw new IllegalArgumentException();
        } catch (Exception e) {
            throw new IllegalArgumentException();
        }
    }

    private Pair<String, String> detectUnsignedDocument(Document document) {
        NodeList signatureNodes = document.getElementsByTagNameNS("*", "Signature");
        if (signatureNodes.getLength() == 0) throw new IllegalArgumentException();
        for (int i = signatureNodes.getLength() - 1; i >= 0; i--) {
            Node node = signatureNodes.item(i);
            node.getParentNode().removeChild(node);
        }

        return new ImmutablePair<>(compressIfNeeded(transformDocument(document)), "");
    }

    private boolean areAttributesIdentical(List<Attribute> firstAttributes, List<Attribute> secondAttributes) {
        if (firstAttributes.size() != secondAttributes.size()) {
            return false;
        }
        for (int i = 0; i < firstAttributes.size(); i++) {
            Attribute a = firstAttributes.get(i);
            Attribute b = secondAttributes.get(i);

            if (!(a.value() == b.value())) {
                return false;
            }
        }
        return true;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        String base = insertionPoint.getBaseValue();
        Optional<Document> document = extractOptionalXMLDocument(base);
        if (document.isEmpty()) return null;

        List<IScanIssue> issues = new ArrayList<>();
        Map<String, CheckDetails> checksCopy = new HashMap<>(this.checks);

        byte[] baseline = insertionPoint.buildRequest(new byte[]{});
        HttpRequest baselineRequest = Utilities.buildMontoyaReq(baseline, basePair.getHttpService());
        HttpRequestResponse baselineRequestResponse = Utilities.montoyaApi.http().sendRequest(baselineRequest);
        if (!baselineRequestResponse.hasResponse()) return null;

        List<Attribute> baselineAttributes = baselineRequestResponse.response().attributes(ATTRIBUTES.toArray(new AttributeType[]{}));
        List<Attribute> originalAttributes = Utilities.buildMontoyaResp(new Resp(basePair)).response().attributes(ATTRIBUTES.toArray(new AttributeType[]{}));

        List<AttributeType> unique = getUniqueAttributeTypes(baselineAttributes, originalAttributes);
        if (unique.isEmpty()) unique = List.of(ATTRIBUTES.toArray(new AttributeType[]{}));

        originalAttributes = Utilities.buildMontoyaResp(new Resp(basePair)).response().attributes(unique.toArray(new AttributeType[]{}));

        while (!checksCopy.isEmpty()) {
            Map.Entry<String, CheckDetails> entry = checksCopy.entrySet().iterator().next();
            checksCopy.remove(entry.getKey());
            String name = entry.getKey();
            Check check = entry.getValue().getTransformation();
            List<String> links = entry.getValue().getLinks();
            String probe;
            try {
                Pair<String, String> result = check.apply(document.get());
                probe = result.getKey();
            } catch (IllegalArgumentException e) {
                continue;
            }
            Utilities.log("Trying " + probe);
            for (int attempt = 0; attempt < this.confirmCount; attempt++) {
                IHttpRequestResponse attack = OldUtilities.request2(basePair, insertionPoint, probe);

                List<Attribute> attackAttributes = Utilities.buildMontoyaResp(new Resp(attack)).response().attributes(unique.toArray(new AttributeType[]{}));
                if (!areAttributesIdentical(attackAttributes, originalAttributes)) continue;
                if (attempt == this.confirmCount - 1) {
                    issues.add(new CustomScanIssue(
                            attack.getHttpService(),
                            helpers.analyzeRequest(attack).getUrl(),
                            new IHttpRequestResponse[]{attack},
                            "Suspicious XML transformation: " + name,
                            "The application seems to support unsafe XML documents in a manner that indicates potential vulnerability (e.g. XXE, Billion Laughs, Round-trip, Namespace Confusion)<br/><br/> "
                                    + "Manual investigation is advised."
                                    + (links.isEmpty() ? "" : "<br/> More details: " + String.join(", ", links)),
                            "Tentative", CustomScanIssue.severity.Information));
                }
            }
        }

        return issues;
    }

    private String transformDocument(Document document) {
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

    public String compressIfNeeded(String data) {
        byte[] resultingData = data.getBytes(StandardCharsets.UTF_8);

        if (isCompressed) {
            byte[] compressedData = compress(resultingData);
            if (compressedData != null) resultingData = compressedData;
        }

        return isBase64Encoded
                ? Base64.getEncoder().encodeToString(resultingData)
                : new String(resultingData, StandardCharsets.ISO_8859_1);

    }

    private byte[] compress(byte[] input) {
        Deflater deflater = new Deflater(5, true);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(input.length)) {
            deflater.setInput(input);
            deflater.finish();
            byte[] buffer = new byte[1024];

            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                outputStream.write(buffer, 0, count);
            }

            return outputStream.toByteArray();
        } catch (IOException e) {
            return null;
        } finally {
            deflater.end();
        }
    }

    public byte[] decompress(byte[] data) throws DataFormatException {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length)) {
            Inflater inflater = new Inflater(true);
            inflater.setInput(data);
            byte[] buffer = new byte[1024];
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                outputStream.write(buffer, 0, count);
            }
            byte[] output = outputStream.toByteArray();
            inflater.end();
            return output;
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private Optional<String> tryURLDecode(String input) {
        try {
            String urlDecoded = URLDecoder.decode(input, StandardCharsets.UTF_8);
            return Optional.of(urlDecoded);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private Optional<byte[]> tryBase64Decode(String input) {
        try {
            byte[] base64Decoded = Base64.getDecoder().decode(input);
            this.isBase64Encoded = true;
            return Optional.of(base64Decoded);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private Optional<String> tryDecompress(byte[] input) {
        try {
            byte[] decompressed = decompress(input);
            this.isCompressed = true;
            return Optional.of(new String(decompressed, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private Optional<Document> parseXML(String xmlString) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setNamespaceAware(true);

            DocumentBuilder builder = factory.newDocumentBuilder();
            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlString.getBytes(StandardCharsets.UTF_8))) {
                Document document = builder.parse(inputStream);
                return Optional.of(document);
            }
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public Optional<Document> extractOptionalXMLDocument(String input) {
        String processedData = tryURLDecode(input).orElse(input);
        Optional<byte[]> optionalBytes = tryBase64Decode(processedData);
        if (optionalBytes.isPresent()) {
            processedData = tryDecompress(optionalBytes.get())
                    .orElse(new String(optionalBytes.get(), StandardCharsets.UTF_8));
        }
        return parseXML(processedData);
    }


    @FunctionalInterface
    private interface Check {
        Pair<String, String> apply(Document base);
    }

    private static class CheckDetails {
        private final Check transformation;
        private final List<String> links;

        public CheckDetails(Check transformation, List<String> usefulLinks) {
            this.transformation = transformation;
            this.links = usefulLinks;
        }

        public Check getTransformation() {
            return transformation;
        }

        public List<String> getLinks() {
            return links.stream()
                    .map(link -> String.format("<a href=\"%s\">%s</a>", link, link)).toList();
        }
    }

}
