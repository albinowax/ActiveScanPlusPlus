package burp;
import java.util.ArrayList;
import java.util.List;

import static burp.PerHostScans.htmlEncode;
import static burp.OldUtilities.randstr;
import static burp.Utilities.callbacks;
import static burp.Utilities.helpers;

public class EdgeSideInclude extends Scan {
    public EdgeSideInclude(String name) {
        super(name);
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        // Generate random canaries
        String canary1 = randstr(4);
        String canary2 = randstr(4);
        String canary3 = randstr(4);

        // Construct the attack payload
        String probe = canary1 + "<!--esi-->" + canary2 + "<!--esx-->" + canary3;
        byte[] payload = insertionPoint.buildRequest(probe.getBytes());

        // Send the attack request
        IHttpRequestResponse attack = callbacks.makeHttpRequest(basePair.getHttpService(), payload);
        String resp = helpers.bytesToString(attack.getResponse());

        // Expected response
        String expect = canary1 + canary2 + "<!--esx-->" + canary3;

        // Check if the expected response is in the actual response
        if (resp.contains(expect)) {
            issues.add(new CustomScanIssue(
                    attack.getHttpService(),
                    helpers.analyzeRequest(attack).getUrl(),
                    new IHttpRequestResponse[] { attack },
                    "Edge Side Include",
                    "The application appears to support Edge Side Includes:<br/><br/> " +
                            "The following probe was sent: <b>" + htmlEncode(probe) +
                            "</b><br/>In the response, the ESI comment has been stripped: <b>" + htmlEncode(expect) +
                            "</b><br/><br/>Refer to https://gosecure.net/2018/04/03/beyond-xss-edge-side-include-injection/ for further information",
                    "Tentative",
                    CustomScanIssue.severity.High
            ));
        }

        return issues;
    }
}
