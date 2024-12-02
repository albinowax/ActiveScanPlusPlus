package burp;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.organizer.Organizer;

import java.util.HashSet;

public class Tester implements HttpHandler {

    private static HashSet<Integer> requestCode = new HashSet<>();

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {

        int hashCode = httpRequestToBeSent.toString().hashCode();
        if (requestCode.contains(hashCode)) {
            httpRequestToBeSent.annotations().setNotes("Seen");
        } else {
            requestCode.add(hashCode);
        }
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }


}


