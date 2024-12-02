package burp;
import java.util.*;

public class PerHostScans extends ParamScan {
    private static Set<String> scannedHosts = new HashSet<>();

    PerHostScans(String name) {
        super(name);
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse basePair) {
        return Collections.emptyList();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        String host = basePair.getHttpService().getHost();
        if (scannedHosts.contains(host)) {
            return Collections.emptyList();
        }

        scannedHosts.add(host);
        List<IScanIssue> issues = new ArrayList<>();
        issues.addAll(interestingFileScan(basePair));
        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

    private static final Object[][] interestingFileMappings = {
            {"/.git/config", "[core]", "source code leak?"},
            {"/server-status", "Server uptime", "debug info"},
            {"/.well-known/apple-app-site-association", "applinks", "https://developer.apple.com/library/archive/documentation/General/Conceptual/AppSearch/UniversalLinks.html"},
            {"/.well-known/openid-configuration", "\"authorization_endpoint\"", "https://portswigger.net/research/hidden-oauth-attack-vectors"},
            {"/.well-known/oauth-authorization-server", "\"authorization_endpoint\"", "https://portswigger.net/research/hidden-oauth-attack-vectors"},
            {"/users/confirmation", "onfirmation token", "Websites using the Devise framework often have a race condition enabling email forgery: https://portswigger.net/research/smashing-the-state-machine"}
    };

    private List<IScanIssue> interestingFileScan(IHttpRequestResponse basePair) {
        List<IScanIssue> issues = new ArrayList<>();
        for (Object[] mapping : interestingFileMappings) {
            String url = (String) mapping[0];
            String expect = (String) mapping[1];
            String reason = (String) mapping[2];

            IHttpRequestResponse attack = fetchURL(basePair, url);
            if (safeBytesToString(attack.getResponse()).contains(expect)) {
                // prevent false positives by tweaking the URL and confirming the expected string goes away
                IHttpRequestResponse baseline = fetchURL(basePair, url.substring(0, url.length() - 1));
                if (!safeBytesToString(baseline.getResponse()).contains(expect)) {
                    issues.add(new CustomScanIssue(
                            basePair.getHttpService(),
                            Utilities.helpers.analyzeRequest(attack).getUrl(),
                            new IHttpRequestResponse[]{attack, baseline},
                            "Interesting response",
                            "The response to <b>" + htmlEncode(url) + "</b> contains <b>'" + htmlEncode(expect) + "'</b><br/><br/>This may be interesting. Here's a clue why: <b>" + htmlEncode(reason) + "</b>",
                            "Firm",
                            CustomScanIssue.severity.Information
                    ));
                }
            }
        }
        return issues;
    }

    private IHttpRequestResponse fetchURL(IHttpRequestResponse basePair, String url) {
        String path = Utilities.helpers.analyzeRequest(basePair).getUrl().getPath();
        String newReq = safeBytesToString(basePair.getRequest()).replaceFirst(path, url);
        return Utilities.callbacks.makeHttpRequest(basePair.getHttpService(), newReq.getBytes());
    }

    // Placeholder methods for helpers and callbacks, assumed to be provided elsewhere
    static String safeBytesToString(byte[] bytes) {
        return new String(bytes);
    }

    static String htmlEncode(String input) {
        // Implement HTML encoding as needed
        return input;
    }
}
