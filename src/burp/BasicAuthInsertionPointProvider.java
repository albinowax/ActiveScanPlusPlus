package burp;
import burp.IScannerInsertionPoint;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BasicAuthInsertionPointProvider implements IScannerInsertionPoint {
    private String baseRequest;
    private int position;
    private String baseBlob;
    private String[] baseValues;
    private int baseOffset;

    public BasicAuthInsertionPointProvider(byte[] baseRequest, int position) {
        this.baseRequest = new String(baseRequest);
        this.position = position;

        Pattern pattern = Pattern.compile("^Authorization: Basic (.*)$", Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(this.baseRequest);
        if (matcher.find()) {
            baseBlob = matcher.group(1);
        } else {
            throw new IllegalArgumentException("Authorization header not found");
        }

        String decodedBlob = new String(Base64.getDecoder().decode(baseBlob));
        baseValues = decodedBlob.split(":");
        baseOffset = this.baseRequest.indexOf(baseBlob);
    }

    @Override
    public String getInsertionPointName() {
        return "BasicAuth" + (position == 0 ? "UserName" : "Password");
    }

    @Override
    public String getBaseValue() {
        return baseValues[position];
    }

    private String makeBlob(byte[] payload) {
        String[] values = baseValues.clone();
        values[position] = new String(payload);
        return Base64.getEncoder().encodeToString(String.join(":", values).getBytes());
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        String newBlob = makeBlob(payload);
        return baseRequest.replace(baseBlob, newBlob).getBytes();
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload) {
        String newBlob = makeBlob(payload);
        return new int[]{baseOffset, baseOffset + newBlob.length()};
    }

    @Override
    public byte getInsertionPointType() {
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED;
    }
}
