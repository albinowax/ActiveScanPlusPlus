package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import org.apache.commons.lang3.tuple.Pair;

import javax.xml.parsers.ParserConfigurationException;
import java.util.*;

import static burp.Utilities.helpers;

public class XMLScan extends ParamScan {
    private final Map<String, CheckDetails> checks;
    private final Set<AttributeType> ATTRIBUTES;
    private final int confirmCount;


    public XMLScan(String name) {
        super(name);
        this.checks = new HashMap<>();
        this.checks.put("DOCTYPE", new CheckDetails(XMLUtilities.SAMLDocument::detectUnsafeDOCTYPE,
                List.of("https://portswigger.net/research/saml-roulette-the-hacker-always-wins")));
        this.checks.put("ENTITY", new CheckDetails(XMLUtilities.SAMLDocument::detectUnsafeENTITIES,
                List.of("https://portswigger.net/research/saml-roulette-the-hacker-always-wins")));
        this.confirmCount = 2;
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
        String insertionPointName = insertionPoint.getInsertionPointName();
        if (!(insertionPointName.equalsIgnoreCase("SAMLRequest") || insertionPointName.equalsIgnoreCase("SAMLResponse")))
            return null;
        Optional<XMLUtilities.SAMLDocument> document = XMLUtilities.SAMLDocument.parse(base);
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
        if (unique.isEmpty()) {
            // Skip target as unpredictable
            return null;
        }

        originalAttributes = Utilities.buildMontoyaResp(new Resp(basePair)).response().attributes(unique.toArray(new AttributeType[]{}));

        while (!checksCopy.isEmpty()) {
            Map.Entry<String, CheckDetails> entry = checksCopy.entrySet().iterator().next();
            checksCopy.remove(entry.getKey());
            String name = entry.getKey();
            Check check = entry.getValue().transformation();
            List<String> links = entry.getValue().links();
            String probe;
            try {
                Pair<String, String> result = check.apply(document.get().copy());
                probe = result.getKey();
            } catch (IllegalArgumentException | ParserConfigurationException e) {
                continue;
            }
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


    @FunctionalInterface
    private interface Check {
        Pair<String, String> apply(XMLUtilities.SAMLDocument base);
    }

    private record CheckDetails(Check transformation, List<String> links) {

        @Override
        public List<String> links() {
                return links.stream()
                        .map(link -> String.format("<a href=\"%s\">%s</a>", link, link)).toList();
            }
        }

}
