package burp;

import burp.api.montoya.core.BurpSuiteEdition;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OldUtilities {
    public static IHttpRequestResponse request2(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint, String attack) {
        return Utilities.callbacks.makeHttpRequest(basePair.getHttpService(), insertionPoint.buildRequest(attack.getBytes()));
    }

    // Placeholder methods for helpers and callbacks, assumed to be provided elsewhere
    public static String safeBytesToString(byte[] bytes) {
        return new String(bytes);
    }

    public static byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    public static String tagmap(String input) {
        StringBuilder tags = new StringBuilder();
        Pattern pattern = Pattern.compile("(?im)(<[a-z]+)");
        Matcher matcher = pattern.matcher(input);
        while (matcher.find()) {
            tags.append(matcher.group());
        }
        return tags.toString();
    }

    public static byte[] setHeader(byte[] request, String name, String value, boolean addIfNotPresent) {
        if (addIfNotPresent) {
            return Utilities.addOrReplaceHeader(request, name, value);
        } else {
            return Utilities.setHeader(request, name, value);
        }

//        // find the end of the headers
//        String prev = "";
//        int i = 0;
//        while (i < request.length) {
//            char thisChar = (char) request[i];
//            if (prev.equals("\n") && thisChar == '\n') {
//                break;
//            }
//            if (prev.equals("\r") && thisChar == '\n' && request[i - 2] == '\n') {
//                break;
//            }
//            prev = String.valueOf(thisChar);
//            i++;
//        }
//        int bodyStart = i;
//
//        // walk over the headers and change as appropriate
//        String headers = new String(Arrays.copyOfRange(request, 0, bodyStart), StandardCharsets.UTF_8);
//        String[] headersArray = headers.split("\r?\n");
//        boolean modified = false;
//        for (int j = 0; j < headersArray.length; j++) {
//            int valueStart = headersArray[j].indexOf(": ");
//            if (valueStart != -1) {
//                String headerNameFound = headersArray[j].substring(0, valueStart);
//                if (headerNameFound.equals(name)) {
//                    String newValue = headerNameFound + ": " + value;
//                    if (!newValue.equals(headersArray[j])) {
//                        headersArray[j] = newValue;
//                        modified = true;
//                    }
//                }
//            }
//        }
//
//        // stitch the request back together
//        byte[] modifiedRequest;
//        if (modified) {
//            modifiedRequest = concatenate(Utilities.helpers.stringToBytes(String.join("\r\n", headersArray) + "\r\n"), Arrays.copyOfRange(request, bodyStart, request.length));
//        } else if (addIfNotPresent) {
//            IRequestInfo requestInfo = Utilities.helpers.analyzeRequest(request);
//            int realStart = requestInfo.getBodyOffset();
//            modifiedRequest = concatenate(Arrays.copyOfRange(request, 0, realStart - 2), Utilities.helpers.stringToBytes(name + ": " + value + "\r\n\r\n"));
//            modifiedRequest = concatenate(modifiedRequest, Arrays.copyOfRange(request, realStart, request.length));
//        } else {
//            modifiedRequest = request;
//        }
//
//        return modifiedRequest;
    }

    public static void launchPassiveScan(IHttpRequestResponse attack) {
        if (Utilities.montoyaApi.burpSuite().version().edition().equals(BurpSuiteEdition.ENTERPRISE_EDITION) || attack.getResponse() == null) {
            return;
        }

        IHttpService service = attack.getHttpService();
        boolean usingHttps = service.getProtocol().equals("https");
        Utilities.callbacks.doPassiveScan(service.getHost(), service.getPort(), usingHttps, attack.getRequest(), attack.getResponse());
    }

    public static boolean hit(byte[] response, String basePrint) {
        return tagmap(safeBytesToString(response)).equals(basePrint);
    }

    public static String randstr(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(length);
        Random rnd = new Random();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
