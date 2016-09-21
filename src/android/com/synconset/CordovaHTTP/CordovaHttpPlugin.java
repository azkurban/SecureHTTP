/**
 * A HTTP plugin for Cordova / Phonegap
 */
package com.synconset;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.net.HttpURLConnection;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.HostnameVerifier;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.res.AssetManager;
import android.util.Base64;
import android.util.Log;

import com.github.kevinsawicki.http.HttpRequest;

public class CordovaHttpPlugin extends CordovaPlugin {
    private static final String TAG = "CordovaHTTP";

//    private static final String API_KEY = "eba670e9-dcfa-4210-9eee-722b4497f5a6";
    private static final String PRIVATE_KEY = "MIIG_wIBADANBgkqhkiG9w0BAQEFAASCBukwggblAgEAAoIBgQD0FJUmrn4kf2_cZekXjmSY-RYZ75yOVLdLeSgTQnM903wp3qdU6-U_uNAx3Qp3CYzKlwkTvzDKOP24fVgIazZk0Z_bWfj2uIrDObbOMqRI9gzDVvmhYONBFHLl0ZU3x7Hh4Z0-8zn8-7zvWRJd2Njh0S_CcCToMLXJDUWKoBc2bNH-Fuw7HGTRFJFM3jE6MzRrE0ZQRVhvUPmYdeA3jFXwQTK_YtmRWwJSoR_pxcZ4Z3ccpGdBA-JHQb9zoZhjpxjf91i2Vhcy0Kwit--vBnDrHQsltxLno8RbxMk1MvG-EkgI6Tihlpkk19rSrgNnwMIrgxz4x9vH_836KCw9DNYPJE3nU8jjjVL7Uvne1yHp7xvzOFQ_oSG9-u7SPtMLgRfjxGf4rtiEv2Lxyxz_xYy1YxLFNdAVzGakkpnDquQJYyt607kUBluT7cpd3jIb6XXpG4HN0zkecBBzUVld_8MbOxjChKvpNX8m6FKD8SXcq4NuksAgH30PIR-UndLXoU0CAwEAAQKCAYEAilYAEuRi6hywMaIw8gDqUykZtalwedrZ6BTK-d93oVrzzGc9P4xTakI8_YXiIIVxHoFry51Y8cRLSP0BoAPj2FBW4eOkj3EYdH2JdmSNaCzMHwp0gVqAcqo8VLTsdajg0L0mej8wZonnE2DQYBA_G_2LrBATWuYAoeq7t0302gvjGLe1O-tj2HxnvcFQ9UOAOg-6klQ7QxwJ2rc0VUdcjcbmFELaPN_v-RUJGV3WlvdNMxaazuZ8oRZKhCbaT-CrxSJCikij4GgFuNMFDTEnfR_u5IAH5XbjZvu8icNljGq758-hxMoPMapeJqUr363iZUT03QYWdcy8sVKYqkloq5Ygeklp7H9HfzZHCEY6_C_X0MBbRj2_Q_JJwWq1--O_tguzx8aldAAOlDehj3xtc2fCfwKWRn4YQfsxV0L8iEbp7R4NHjL0hJTeDSVCbjy4vCyEoADagU_vvb0dCUhcB_u4xI0SltlhA3-bD9n1pZnxaM3EtEurzwRbh1ElF2WhAoHBAP296-fZHT95hF-QsuZ1_f5HMbDbbozj_AhelpBZRcYOldB9yFOuBnoJiCcSqf3f-YxOp2EZI_ANrm1J0wSUaboiKZJe73FqflmC2ML7_v67Hdimrqsf1ScWVoYHNfsBL8NQfMnvaFGS60wdyptyHG9LXFVUasy86Hlo9kseGn_r6l2jK309NDvmYNe6WnaBI06B4jZtHmZKsEhmh9gx_kIJfy3Y2xw5j8gvuGbM6tOoT14L97wBS0KgonNM9pHEJwKBwQD2QKZyxhmzvarfKFrU30MiKBX3UajWfANycngUD8QCfQzK5MioeMiCmblF20piCVmcHylvW3AHV2Rt8RTRPXYqyCpIpd1R320KXh5cqRraJXbLR_TSQE9jxTzpGw6Lqckuw8yc5PNMAJ2pfmpwB172RhjdWNcwxS1Wa9W9HDoaj-KjD9dxZwvxr4GMu81d2Ih3Yvo0gDjPHwcVKPA-sf-fMQsa_8t7Bgaow_hYp5VoSqrdh9j5GEtPAm24vo1eU2sCgcEA_TcfiVJQbrycjiW_cl8DZlKz0vNX4j_NjqieBlUgXSLG_LXZSTCchAKpHZzxiUmPJiaDwFEvXOq6S5Plgmd9DuPyqoAU4RDOIBOEryh88sXWZhMIsfrlYslW9Q-THfa0LGxQ68__QZClQWNlgjShDaud7AV_Quut7yMAzjuvZEMQsfsYdjWyv6gKsp3kkugSTNEu5vOD577XJpkzLVvOiSYjBaSoHAWRZ8u_cM9D9I69DXRR-AsuiMH2-6stUI_3AoHBAOjLF09bTULpI9bQ7IVfBrUMli926BjTpeKUqkW03cTIeMZ53-O8QzmLn2WVuEzTr_3yS5Z1J4QZLtzsUpS3-LTbA3YoLwDOKePqM-O_DZ56WkI0JRJ6L1MPS9TGekq32HO4L_-GRSZtUp6_3llH7pL8k1b1PIFjdcfEK4waWidwLH2gZThUhSsWkm77v1pfcCsEy6nEKXBMUcLEL9HlLdVNZMVCWhdUDAmRMX6F9q1gIQVJ_mkFeXQYxKcopLYuPwKBwAQRp01zH9RHRfTLSO39-t9agv5_23mf3GDkBfZlO7qzKpwyQ5WNPdvGtYNL2dDbqNjvLDDsB3NUt9v3esAq8hCpVkHFvDaZHlpwlPGuVwK2MAVwJ71DtCHYXwq5oPdxR6_A1lFE9b1V9gDle1i2OcHM81C7AB286IQSO8uTP6qucqPIE-u24bOeFmYUHdYe31xtFtWxGDh9AVmJWRRy69ZviXnSayKbWwM3znn5JKGKs_Vs9ZIp6MxxhG2wGIqfPQ";

    private static final String HEADER_DATE = "Date";
    private static final String HEADER_CONTECT_MD5 = "Content-MD5";
    private static final String HEADER_API = "X-Fara-ApiKey";
    private static final String HEADER_SIGNATURE = "X-Fara-Signature";

    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
//!GP!    private static final Base64.Decoder BASE_64_DECODER = Base64.getUrlDecoder();
//!GP!    private static final Base64.Encoder BASE_64_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private static byte[] mPrivateKey = null;


    private static byte[] getPrivateKey() {
        if (mPrivateKey == null)
//!GP!        mPrivateKey = BASE_64_DECODER.decode(PRIVATE_KEY);
            mPrivateKey = Base64.decode(PRIVATE_KEY, Base64.DEFAULT);

        return mPrivateKey;
    }

    private static Map<String, String> setHeaderSignature(String method, String path,
                                         HashMap<String, String> headers,
                                         Map<String, String> params)
            throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        String data = createCanonicalRepresentation(method, path, headers, params);
        String signature = createSignature(data);
        headers.put(HEADER_SIGNATURE, signature);
        return headers;
    }

    private static List<String> getSortedKeys(Map<String, ?> map) {
        List<String> keys = new ArrayList<String>(map.keySet());
        Collections.sort(keys, new Comparator<String>() {
            @Override
            public int compare(String lhs, String rhs) {
                if (lhs == null) return rhs == null ? 0 : -1;
                if (rhs == null) return 1;
                return lhs.compareTo(rhs);
            }
        });
        return keys;
    }

    private static String createCanonicalRepresentation(String method, String path,
                                                        Map<String, String> headers,
                                                        Map<String, String> queryParameters)
    {
        String canonicalRepresentation = method.toUpperCase() + "\n";
        canonicalRepresentation += path + "\n";


        for (String key : getSortedKeys(headers)) {
            canonicalRepresentation += key.toLowerCase() + ": " +  headers.get(key) + "\n";
        }

        if (queryParameters != null && queryParameters.size() > 0) {
            boolean first = true;
            for (String key : getSortedKeys(queryParameters)) {
                if (first)
                    first = false;
                else
                    canonicalRepresentation += '&';
                canonicalRepresentation += key + "=" + queryParameters.get(key);
            }
        }
        canonicalRepresentation += "\n";

        return canonicalRepresentation;
    }

    private static String createSignature(String canonicalRepresentation)
            throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException
    {
        final KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException(KEY_ALGORITHM, e);
        }

        final byte[] privateKeyBytes = getPrivateKey();
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
//!GP!            signatureAsString = BASE_64_ENCODER.encodeToString(sig.sign());
            signatureAsString = Base64.encodeToString(sig.sign(), Base64.NO_PADDING);
        } catch (SignatureException e) {
            throw new SignatureException(e);
        }

        return signatureAsString;
    }

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
    }

    @Override
    public boolean execute(String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if (action.equals("get")) {
            String urlString = args.getString(0);
            JSONObject params = args.getJSONObject(1);
            JSONObject headers = args.getJSONObject(2);
            HashMap<?, ?> paramsMap = this.getMapFromJSONObject(params);
            HashMap<String, String> headersMap = this.getStringMapFromJSONObject(headers);
            setHeaderSignature("GET", urlString, headersMap, paramsMap);
            CordovaHttpGet get = new CordovaHttpGet(urlString, paramsMap, headersMap, callbackContext);
            cordova.getThreadPool().execute(get);
        } else if (action.equals("head")) {
            String urlString = args.getString(0);
            JSONObject params = args.getJSONObject(1);
            JSONObject headers = args.getJSONObject(2);
            HashMap<?, ?> paramsMap = this.getMapFromJSONObject(params);
            HashMap<String, String> headersMap = this.getStringMapFromJSONObject(headers);
            CordovaHttpHead head = new CordovaHttpHead(urlString, paramsMap, headersMap, callbackContext);
            cordova.getThreadPool().execute(head);
        } else if (action.equals("post")) {
            String urlString = args.getString(0);
            JSONObject params = args.getJSONObject(1);
            JSONObject headers = args.getJSONObject(2);
            HashMap<?, ?> paramsMap = this.getMapFromJSONObject(params);
            HashMap<String, String> headersMap = this.getStringMapFromJSONObject(headers);
            CordovaHttpPost post = new CordovaHttpPost(urlString, paramsMap, headersMap, callbackContext);
            cordova.getThreadPool().execute(post);
        } else if (action.equals("postJson")) {
            String urlString = args.getString(0);
            JSONObject jsonObj = args.getJSONObject(1);
            JSONObject headers = args.getJSONObject(2);
            HashMap<String, String> headersMap = this.getStringMapFromJSONObject(headers);
            setHeaderSignature("POST", urlString, headersMap, null);
            CordovaHttpPostJson postJson = new CordovaHttpPostJson(urlString, jsonObj, headersMap, callbackContext);
            cordova.getThreadPool().execute(postJson);
        } else if (action.equals("postJsonString")) {
            String urlString = args.getString(0);
            String jsonString = args.getString(1);
            JSONObject headers = args.getJSONObject(2);
            HashMap<String, String> headersMap = this.getStringMapFromJSONObject(headers);
            setHeaderSignature("POST", urlString, headersMap, null);
            CordovaHttpPostJsonString postJsonString = new CordovaHttpPostJsonString(urlString, jsonString, headersMap, callbackContext);
            cordova.getThreadPool().execute(postJsonString);
        } else if (action.equals("put")) {
            String urlString = args.getString(0);
            JSONObject params = args.getJSONObject(1);
            JSONObject headers = args.getJSONObject(2);
            HashMap<?, ?> paramsMap = this.getMapFromJSONObject(params);
            HashMap<String, String> headersMap = this.getStringMapFromJSONObject(headers);
            CordovaHttpPut put = new CordovaHttpPut(urlString, paramsMap, headersMap, callbackContext);
            cordova.getThreadPool().execute(put);
        } else if (action.equals("putJson")) {
            String urlString = args.getString(0);
            JSONObject jsonObj = args.getJSONObject(1);
            JSONObject headers = args.getJSONObject(2);
            HashMap<String, String> headersMap = this.getStringMapFromJSONObject(headers);
            setHeaderSignature("PUT", urlString, headersMap, null);
            CordovaHttpPutJson putJson = new CordovaHttpPutJson(urlString, jsonObj, headersMap, callbackContext);
            cordova.getThreadPool().execute(putJson);
        } else if (action.equals("delete")) {
            String urlString = args.getString(0);
            JSONObject params = args.getJSONObject(1);
            JSONObject headers = args.getJSONObject(2);
            HashMap<?, ?> paramsMap = this.getMapFromJSONObject(params);
            HashMap<String, String> headersMap = this.getStringMapFromJSONObject(headers);
            CordovaHttpDelete delete = new CordovaHttpDelete(urlString, paramsMap, headersMap, callbackContext);
            cordova.getThreadPool().execute(delete);
        } else if (action.equals("enableSSLPinning")) {
            try {
                boolean enable = args.getBoolean(0);
                this.enableSSLPinning(enable);
                callbackContext.success();
            } catch(Exception e) {
                e.printStackTrace();
                callbackContext.error("There was an error setting up ssl pinning");
            }
        } else if (action.equals("acceptAllCerts")) {
            boolean accept = args.getBoolean(0);
            CordovaHttp.acceptAllCerts(accept);
            callbackContext.success();
        } else if (action.equals("validateDomainName")) {
            boolean accept = args.getBoolean(0);
            CordovaHttp.validateDomainName(accept);
            callbackContext.success();
        } else if (action.equals("uploadFile")) {
            String urlString = args.getString(0);
            JSONObject params = args.getJSONObject(1);
            JSONObject headers = args.getJSONObject(2);
            HashMap<?, ?> paramsMap = this.getMapFromJSONObject(params);
            HashMap<String, String> headersMap = this.getStringMapFromJSONObject(headers);
            String filePath = args.getString(3);
            String name = args.getString(4);
            CordovaHttpUpload upload = new CordovaHttpUpload(urlString, paramsMap, headersMap, callbackContext, filePath, name);
            cordova.getThreadPool().execute(upload);
        } else if (action.equals("downloadFile")) {
            String urlString = args.getString(0);
            JSONObject params = args.getJSONObject(1);
            JSONObject headers = args.getJSONObject(2);
            HashMap<?, ?> paramsMap = this.getMapFromJSONObject(params);
            HashMap<String, String> headersMap = this.getStringMapFromJSONObject(headers);
            String filePath = args.getString(3);
            CordovaHttpDownload download = new CordovaHttpDownload(urlString, paramsMap, headersMap, callbackContext, filePath);
            cordova.getThreadPool().execute(download);
        } else {
            return false;
        }
        return true;
    }

    private void enableSSLPinning(boolean enable) throws GeneralSecurityException, IOException {
        if (enable) {
            AssetManager assetManager = cordova.getActivity().getAssets();
            String[] files = assetManager.list("");
            int index;
            ArrayList<String> cerFiles = new ArrayList<String>();
            for (int i = 0; i < files.length; i++) {
                index = files[i].lastIndexOf('.');
                if (index != -1) {
                    if (files[i].substring(index).equals(".cer")) {
                        cerFiles.add(files[i]);
                    }
                }
            }

            // scan the www/certificates folder for .cer files as well
            files = assetManager.list("www/certificates");
            for (int i = 0; i < files.length; i++) {
              index = files[i].lastIndexOf('.');
              if (index != -1) {
                if (files[i].substring(index).equals(".cer")) {
                  cerFiles.add("www/certificates/" + files[i]);
                }
              }
            }

            for (int i = 0; i < cerFiles.size(); i++) {
                InputStream in = cordova.getActivity().getAssets().open(cerFiles.get(i));
                InputStream caInput = new BufferedInputStream(in);
                HttpRequest.addCert(caInput);
            }
            CordovaHttp.enableSSLPinning(true);
        } else {
            CordovaHttp.enableSSLPinning(false);
        }
    }

    private HashMap<String, String> getStringMapFromJSONObject(JSONObject object) throws JSONException {
        HashMap<String, String> map = new HashMap<String, String>();
        Iterator<?> i = object.keys();

        while (i.hasNext()) {
            String key = (String)i.next();
            map.put(key, object.getString(key));
        }
        return map;
    }

    private HashMap<String, Object> getMapFromJSONObject(JSONObject object) throws JSONException {
        HashMap<String, Object> map = new HashMap<String, Object>();
        Iterator<?> i = object.keys();

        while(i.hasNext()) {
            String key = (String)i.next();
            map.put(key, object.get(key));
        }
        return map;
    }
}
