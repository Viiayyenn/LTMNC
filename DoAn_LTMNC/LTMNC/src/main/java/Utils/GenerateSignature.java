package Utils;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

public class GenerateSignature {

    public static String sign(String data, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data.getBytes());
        byte[] signature = signer.sign();
        return Base64.getEncoder().encodeToString(signature);
    }
}
