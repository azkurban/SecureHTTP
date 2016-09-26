import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

public class SignatureExample {

    private static final String API_KEY = "";
    private static final String PRIVATE_KEY = "";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    private static final Base64.Decoder BASE_64_DECODER = Base64.getUrlDecoder();
    private static final Base64.Encoder BASE_64_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Charset UTF_8 = Charset.forName("UTF-8");

/*
    public static void main(String[] args) {
        try {
            TreeMap<String, String> headers = new TreeMap<>();
            headers.put("X-Fara-ApiKey", API_KEY);
            headers.put("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg");
            headers.put("Date", "Mon, 01 Aug 2016 14:01:46 GMT");
            final String canonicalRepresentation = createCanonicalRepresentation("GET", "/api/v1.0/ptas/", headers, new TreeMap<>());
            System.out.println("Canonical representation:");
            System.out.println(canonicalRepresentation);

            final String signature = createSignature(canonicalRepresentation, PRIVATE_KEY);
            System.out.println("");
            System.out.println("Signature:");
            System.out.println(signature);
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
*/
    private static String createCanonicalRepresentation(String method, String path, SortedMap<String, String> headers, SortedMap<String, String> queryParameters) {

        String canonicalRepresentation = method.toUpperCase() + "\n";

        canonicalRepresentation += path + "\n";

        for (Map.Entry<String, String> entry : headers.entrySet()) {
            canonicalRepresentation += entry.getKey().toLowerCase() + ": " + entry.getValue() + "\n";
        }

        String separator = "";
        for (Map.Entry<String, String> entry : queryParameters.entrySet()) {
            canonicalRepresentation += separator + entry.getKey() + "=" + entry.getValue();
            separator = "&";
        }
        canonicalRepresentation += "\n";

        return canonicalRepresentation;
    }

    private static String createSignature(String canonicalRepresentation, String privateKey) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        final KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException(KEY_ALGORITHM, e);
        }
        final byte[] privateKeyBytes = BASE_64_DECODER.decode(privateKey);
        final EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        final Signature sig;
        try {
            sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException(SIGNATURE_ALGORITHM, e);
        }

        try {
            sig.initSign(keyFactory.generatePrivate(privateKeySpec));
        } catch (InvalidKeyException e) {
            throw new InvalidKeyException(e);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeySpecException(e);
        }

        final String signatureAsString;
        try {
            sig.update(canonicalRepresentation.getBytes(UTF_8));
            signatureAsString = BASE_64_ENCODER.encodeToString(sig.sign());
        } catch (SignatureException e) {
            throw new SignatureException(e);
        }

        return signatureAsString;
    }
}