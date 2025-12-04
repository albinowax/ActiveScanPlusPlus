package burp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

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
        issues.addAll(rscRceScan(basePair));
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

    private List<IScanIssue> rscRceScan(IHttpRequestResponse basePair) {
        IHttpRequestResponse exploitResponse = sendRscExploit(basePair);

        if (isVulnerableToRsc(exploitResponse)) {
            return List.of(createRscIssue(basePair, exploitResponse));
        }

        return List.of();
    }


    private IHttpRequestResponse sendRscExploit(IHttpRequestResponse basePair) {
        String boundary = "----WebKitFormBoundary" + Utilities.randomString(16);

        StringBuilder payload = new StringBuilder();

        // Field "1" with empty object
        payload.append("--").append(boundary).append("\r\n");
        payload.append("Content-Disposition: form-data; name=\"1\"\r\n\r\n");
        payload.append("{}\r\n");

        // Field "0" with malicious property reference
        payload.append("--").append(boundary).append("\r\n");
        payload.append("Content-Disposition: form-data; name=\"0\"\r\n\r\n");
        payload.append("[\"$1:a:a\"]\r\n");

        payload.append("--").append(boundary).append("--\r\n");

        // Build the request
        IRequestInfo requestInfo = Utilities.helpers.analyzeRequest(basePair);
        List<String> headers = new ArrayList<>(requestInfo.getHeaders());

        // Remove existing headers that we'll replace
        headers.removeIf(h -> h.toLowerCase().startsWith("content-type:") ||
                              h.toLowerCase().startsWith("content-length:") ||
                              h.toLowerCase().startsWith("next-action:") ||
                              h.toLowerCase().startsWith("x-nextjs-request-id:") ||
                              h.toLowerCase().startsWith("next-router-state-tree:"));

        // Modify first line to POST to root
        headers.set(0, "POST / HTTP/1.1");

        // Add required headers
        headers.add("Content-Type: multipart/form-data; boundary=" + boundary);
        headers.add("Content-Length: " + payload.length());
        headers.add("Next-Action: " + Utilities.randomString(32));
        headers.add("X-Nextjs-Request-Id: " + UUID.randomUUID());
        headers.add("Next-Router-State-Tree: [[[\"\"," +
                   "{\\\"children\\\":[\\\"__PAGE__\\\",{}]},null,null,true]]");

        // Build full request
        byte[] requestBytes = Utilities.helpers.buildHttpMessage(headers, payload.toString().getBytes());

        return Utilities.callbacks.makeHttpRequest(basePair.getHttpService(), requestBytes);
    }

    private boolean isVulnerableToRsc(IHttpRequestResponse response) {
        if (response != null && response.getResponse() != null)
        {
            IResponseInfo responseInfo = Utilities.helpers.analyzeResponse(response.getResponse());
            if (responseInfo.getStatusCode() == 500)
            {
                String body = safeBytesToString(response.getResponse());

                // Look for Next.js error digest pattern indicating the exploit triggered
                return body.contains("E{\"digest\"") ||
                       (body.contains("digest") && body.contains("Error"));
            }
        }

        return false;
    }

    private IScanIssue createRscIssue(IHttpRequestResponse baseRequestResponse,
                                      IHttpRequestResponse exploitResponse) {
        String errorSnippet = extractErrorSnippet(exploitResponse);

        String detail = "<p>The application is <b>vulnerable to CVE-2025-55182</b> (React) and " +
                       "<b>CVE-2025-66478</b> (Next.js), critical Remote Code Execution vulnerabilities " +
                       "in React Server Components with CVSS score of 10.0.</p>" +
                       "<p><b>Vulnerability Overview:</b></p>" +
                       "<ul>" +
                       "<li>Unauthenticated Remote Code Execution via insecure deserialization</li>" +
                       "<li>The RSC Flight protocol fails to validate property existence in colon-delimited references</li>" +
                       "<li>Malformed multipart form-data triggers unhandled exceptions leading to RCE</li>" +
                       "<li>No prerequisites or special configuration required for exploitation</li>" +
                       "</ul>" +
                       "<p><b>Detection Evidence:</b></p>" +
                       "<ul>" +
                       "<li>✓ HTTP 500 status code received</li>" +
                       "<li>✓ Next.js error digest pattern detected in response</li>" +
                       "<li>✓ Server failed to handle malicious property reference: <code>[\"$1:a:a\"]</code></li>" +
                       "</ul>" +
                       "<p><b>Error Details:</b></p>" +
                       "<pre>" + htmlEncode(errorSnippet) + "</pre>" +
                       "<p><b>CRITICAL - Immediate Action Required</b></p>" +
                       "<p>This vulnerability allows unauthenticated attackers to execute arbitrary code on the server. " +
                       "Patch immediately.</p>" +
                       "<p><b>Upgrade to Patched Versions:</b></p>" +
                       "<ul>" +
                       "<li><b>React:</b> 19.0.1, 19.1.2, or 19.2.1</li>" +
                       "<li><b>Next.js:</b> 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, or 16.0.7</li>" +
                       "</ul>" +
                       "<p><b>Remediation Steps:</b></p>" +
                       "<ol>" +
                       "<li>Update package.json dependencies to patched versions</li>" +
                       "<li>Run: <code>npm install</code> or <code>npm update</code></li>" +
                       "<li>Rebuild and redeploy application</li>" +
                       "<li>Verify fix by re-scanning</li>" +
                       "</ol>" +
                       "<p><b>References:</b></p>" +
                       "<ul>" +
                       "<li><a href=\"https://nextjs.org/blog/CVE-2025-66478\">Next.js Security Advisory</a></li>" +
                       "<li><a href=\"https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182\">CVE-2025-55182 Details</a></li>" +
                       "<li><a href=\"https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478/\">Detection of CVE-2025-55182</a></li>" +
                       "</ul>";

        return new CustomScanIssue(
                baseRequestResponse.getHttpService(),
                Utilities.helpers.analyzeRequest(baseRequestResponse).getUrl(),
                new IHttpRequestResponse[]{baseRequestResponse, exploitResponse},
                "CVE-2025-55182 / CVE-2025-66478 React2Shell",
                detail,
                "Certain",
                CustomScanIssue.severity.High
        );
    }

    private String extractErrorSnippet(IHttpRequestResponse response) {
        if (response == null || response.getResponse() == null) {
            return "No error details available";
        }

        String body = safeBytesToString(response.getResponse());

        // Try to extract digest and surrounding context
        int digestIndex = body.indexOf("digest");
        if (digestIndex != -1) {
            int start = Math.max(0, digestIndex - 50);
            int end = Math.min(body.length(), digestIndex + 150);
            return "..." + body.substring(start, end) + "...";
        }

        // Return first 300 characters if no digest found
        return body.length() > 300 ? body.substring(0, 300) + "..." : body;
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
