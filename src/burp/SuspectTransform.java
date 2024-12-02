package burp;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;
import java.util.Random;

import static burp.PerHostScans.safeBytesToString;
import static burp.Utilities.helpers;

public class SuspectTransform extends ParamScan {
    private Map<String, Check> checks;
    private int confirmCount;

    public SuspectTransform(String name) {
        super(name);
        this.checks = new HashMap<>();
        this.checks.put("quote consumption", this::detectQuoteConsumption);
        this.checks.put("arithmetic evaluation", this::detectArithmetic);
        this.checks.put("expression evaluation", this::detectExpression);
        this.checks.put("template evaluation", this::detectRazorExpression);
        this.checks.put("EL evaluation", this::detectAltExpression);

        this.confirmCount = 2;
    }

    private Pair<String, List<String>> detectQuoteConsumption(String base) {
        return new ImmutablePair<>("''", Collections.singletonList("'"));
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
        Map<String, Check> checksCopy = new HashMap<>(this.checks);

        while (!checksCopy.isEmpty()) {
            Map.Entry<String, Check> entry = checksCopy.entrySet().iterator().next();
            checksCopy.remove(entry.getKey());
            String name = entry.getKey();
            Check check = entry.getValue();

            for (int attempt = 0; attempt < confirmCount; attempt++) {
                Pair<String, List<String>> result = check.apply(base);
                String probe = result.getKey();
                List<String> expect = result.getValue();

                Utilities.log("Trying " + probe);
                IHttpRequestResponse attack = OldUtilities.request2(basePair, insertionPoint, probe);
                String attackResponse = safeBytesToString(attack.getResponse());

                boolean matched = false;
                for (String e : expect) {
                    if (attackResponse.contains(e) && !initialResponse.contains(e)) {
                        matched = true;
                        if (attempt == confirmCount - 1) {
                            issues.add(new CustomScanIssue(
                                    attack.getHttpService(),
                                    helpers.analyzeRequest(attack).getUrl(),
                                    new IHttpRequestResponse[]{attack},
                                    "Suspicious input transformation: " + name,
                                    "The application transforms input in a way that suggests it might be vulnerable to some kind of server-side code injection:<br/><br/> "
                                            + "The following probe was sent: <b>" + probe + "</b><br/>"
                                            + "The server response contained the evaluated result: <b>" + e + "</b><br/><br/>Manual investigation is advised.",
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

    @FunctionalInterface
    private interface Check {
        Pair<String, List<String>> apply(String base);
    }

    // Other utility methods like safeBytesToString, request, debugMsg, etc. should be implemented as needed.
}