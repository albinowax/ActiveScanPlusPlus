package burp;
import java.util.ArrayList;
import java.util.List;

import static burp.PerHostScans.safeBytesToString;
import static burp.Utilities.helpers;
import static burp.OldUtilities.request2;

public class JetLeak extends ParamScan {

    public JetLeak(String name) {
        super(name);
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        if (!"Referer".equals(insertionPoint.getInsertionPointName())) {
            return new ArrayList<>();
        }
        IHttpRequestResponse attack = request2(basePair, insertionPoint, "\\x00");
        String respStart = safeBytesToString(attack.getResponse()).substring(0, 90);
        List<IScanIssue> issues = new ArrayList<>();
        if (respStart.contains("400 Illegal character 0x0 in state") && respStart.contains("<<<")) {
            issues.add(new CustomScanIssue(
                    attack.getHttpService(),
                    helpers.analyzeRequest(attack).getUrl(),
                    new IHttpRequestResponse[]{attack},
                    "CVE-2015-2080 (JetLeak)",
                    "The application appears to be running a version of Jetty vulnerable to CVE-2015-2080, which allows attackers to read out private server memory.<br/>"
                            + "Please refer to http://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html for further information",
                    "Firm",
                    CustomScanIssue.severity.High
            ));
        }
        return issues;
    }
}
