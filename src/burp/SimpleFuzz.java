package burp;

import java.util.ArrayList;
import java.util.List;

import static burp.OldUtilities.launchPassiveScan;
import static burp.OldUtilities.tagmap;
import static burp.Utilities.callbacks;
import static burp.Utilities.helpers;


public class SimpleFuzz extends ParamScan {

    public SimpleFuzz(String name) {
        super(name);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();

        // Construct the attack payload
        byte[] payload = insertionPoint.buildRequest("a'a\\'b\"c>?>%}}%%>c<[[?${{%}}cake\\".getBytes());

        // Send the attack request
        IHttpRequestResponse attack = callbacks.makeHttpRequest(basePair.getHttpService(), payload);

        // Compare the response
        if (!tagmap(helpers.bytesToString(attack.getResponse())).equals(tagmap(helpers.bytesToString(basePair.getResponse())))) {
            // Launch passive scan if the responses are different
            launchPassiveScan(attack);
        }

        return issues;
    }


}
