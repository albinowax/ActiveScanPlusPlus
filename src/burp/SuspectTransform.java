package burp;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;
import java.util.Random;

import static burp.PerHostScans.safeBytesToString;
import static burp.Utilities.helpers;

public class SuspectTransform extends ParamScan {
    private Map<String, CheckDetails> checks;
    private int confirmCount;

    public SuspectTransform(String name) {
        super(name);
        this.checks = new HashMap<>();
        this.checks.put("quote consumption", new CheckDetails(this::detectQuoteConsumption, List.of()));
        this.checks.put("arithmetic evaluation", new CheckDetails(this::detectArithmetic, List.of()));
        this.checks.put("expression evaluation", new CheckDetails(this::detectExpression,
                List.of("https://portswigger.net/research/server-side-template-injection")));
        this.checks.put("template evaluation", new CheckDetails(this::detectRazorExpression,
                List.of("https://portswigger.net/research/server-side-template-injection")));
        this.checks.put("EL evaluation", new CheckDetails(this::detectAltExpression,
                List.of("https://portswigger.net/research/server-side-template-injection")));
        this.checks.put("unicode normalisation", new CheckDetails(this::detectUnicodeNormalisation,
                List.of("https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/")));
        this.checks.put("url decoding error", new CheckDetails(this::detectUrlDecodeError,
                List.of("https://cwe.mitre.org/data/definitions/172.html")));
        this.checks.put("unicode byte truncation", new CheckDetails(this::detectUnicodeByteTruncation,
                List.of("https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows")));
        this.checks.put("unicode case conversion", new CheckDetails(this::detectUnicodeCaseConversion,
                List.of("https://www.unicode.org/charts/case/index.html")));
        this.checks.put("unicode combining diacritic", new CheckDetails(this::detectUnicodeCombiningDiacritic,
                List.of("https://codepoints.net/combining_diacritical_marks?lang=en")));
        this.confirmCount = 2;
    }
    
    private Pair<String, List<String>> detectUnicodeNormalisation(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);
        return new ImmutablePair<>(leftAnchor+"\u212a"+rightAnchor, Collections.singletonList(leftAnchor+"K"+rightAnchor));
    }

    private Pair<String, List<String>> detectUrlDecodeError(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);
        return new ImmutablePair<>(leftAnchor+"\u0391"+rightAnchor, Collections.singletonList(leftAnchor+"N\u0011"+rightAnchor));
    }

    private Pair<String, List<String>> detectUnicodeByteTruncation(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);
        return new ImmutablePair<>(leftAnchor+"\uCF7B"+rightAnchor, Collections.singletonList(leftAnchor+"{"+rightAnchor));
    }

    private Pair<String, List<String>> detectUnicodeCaseConversion(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);
        return new ImmutablePair<>(leftAnchor+"\u0131"+rightAnchor, Collections.singletonList(leftAnchor+"I"+rightAnchor));
    }

    private Pair<String, List<String>> detectUnicodeCombiningDiacritic(String base) {
        String rightAnchor = Utilities.randomString(6);
        return new ImmutablePair<>("\u0338"+rightAnchor, Collections.singletonList("\u226F"+rightAnchor));
    }

    private Pair<String, List<String>> detectQuoteConsumption(String base) {
        String leftAnchor = Utilities.randomString(6);
        String rightAnchor = Utilities.randomString(6);
        return new ImmutablePair<>(leftAnchor+"''"+rightAnchor, Collections.singletonList(leftAnchor+"'"+rightAnchor));
    }

    private Pair<String, List<String>> detectArithmetic(String base) {
        Random random = new Random();
        int x = 99 + random.nextInt(9901);
        int y = 99 + random.nextInt(9901);
        String probe = x + "*" + y;
        String expect = String.valueOf(x * y);
        return new ImmutablePair<>(probe, Collections.singletonList(expect));
    }

    private Pair<String, List<String>> detectExpression(String base) {
        Pair<String, List<String>> arithmeticResult = detectArithmetic(base);
        String probe = "${" + arithmeticResult.getKey() + "}";
        return new ImmutablePair<>(probe, arithmeticResult.getValue());
    }

    private Pair<String, List<String>> detectAltExpression(String base) {
        Pair<String, List<String>> arithmeticResult = detectArithmetic(base);
        String probe = "%{" + arithmeticResult.getKey() + "}";
        return new ImmutablePair<>(probe, arithmeticResult.getValue());
    }

    private Pair<String, List<String>> detectRazorExpression(String base) {
        Pair<String, List<String>> arithmeticResult = detectArithmetic(base);
        String probe = "@(" + arithmeticResult.getKey() + ")";
        return new ImmutablePair<>(probe, arithmeticResult.getValue());
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        String base = insertionPoint.getBaseValue();
        String initialResponse = safeBytesToString(basePair.getResponse());
        List<IScanIssue> issues = new ArrayList<>();
        Map<String, CheckDetails> checksCopy = new HashMap<>(this.checks);

        while (!checksCopy.isEmpty()) {
            Map.Entry<String, CheckDetails> entry = checksCopy.entrySet().iterator().next();
            checksCopy.remove(entry.getKey());
            String name = entry.getKey();
            Check check = entry.getValue().getTransformation();
            List<String> links = entry.getValue().getLinks();

            for (int attempt = 0; attempt < confirmCount; attempt++) {
                Pair<String, List<String>> result = check.apply(base);
                String probe = result.getKey();
                List<String> expect = result.getValue();

                Utilities.log("Trying " + probe);
                IHttpRequestResponse attack = OldUtilities.request2(basePair, insertionPoint, probe);
                String attackResponse = safeBytesToString(attack.getResponse());

                boolean matched = false;
                for (String e : expect) {
                    boolean attackContains = containsExpectedValue(attackResponse, e);
                    boolean initialContains = containsExpectedValue(initialResponse, e);
                    if (attackContains && !initialContains) {
                        matched = true;
                        if (attempt == confirmCount - 1) {
                            issues.add(new CustomScanIssue(
                                    attack.getHttpService(),
                                    helpers.analyzeRequest(attack).getUrl(),
                                    new IHttpRequestResponse[]{attack},
                                    "Suspicious input transformation: " + name,
                                    "The application transforms input in a manner that indicates potential vulnerability (e.g., code injection, validation bypass, etc.):<br/><br/> "
                                            + "The following probe was sent: <b>" + probe + "</b><br/>"
                                            + "The server response contained the evaluated result: <b>" + e + "</b><br/><br/>Manual investigation is advised."
                                            + (links.isEmpty() ? "" : "<br/> More details: " + String.join(", ", links)),
                                    "Tentative", CustomScanIssue.severity.High));
                        }
                        break;
                    }
                }

                if (!matched) {
                    break;
                }
            }
        }

        return issues;
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

    @FunctionalInterface
    private interface Check {
        Pair<String, List<String>> apply(String base);
    }

    private boolean containsExpectedValue(String body, String expected) {
        if (body == null || expected == null) {
            return false;
        }

        if (expected.chars().allMatch(Character::isDigit)) {
            return containsIsolatedNumber(body, expected);
        }

        return body.contains(expected);
    }

    private boolean containsIsolatedNumber(String body, String number) {
        if (body == null || number == null || number.isEmpty()) {
            return false;
        }

        int index = -1;
        while ((index = body.indexOf(number, index + 1)) != -1) {
            if (hasValidNumberBoundaries(body, index, number.length())) {
                return true;
            }
        }

        return false;
    }

    private boolean hasValidNumberBoundaries(String body, int startIndex, int length) {
        // Numbers may not be preceded by another digit or a decimal point
        int prefixIndex = startIndex - 1;
        boolean validPrefix = prefixIndex < 0
                || (!Character.isDigit(body.charAt(prefixIndex)) && body.charAt(prefixIndex) != '.');

        // Numbers must not be terminated with another digit
        int suffixIndex = startIndex + length;
        boolean validSuffix = suffixIndex >= body.length() || !Character.isDigit(body.charAt(suffixIndex));

        return validPrefix && validSuffix;
    }

    // Other utility methods like safeBytesToString, request, debugMsg, etc. should be implemented as needed.
}
