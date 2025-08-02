package Utils;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class VerifySignature {

    public static boolean verify(String data, String signatureStr, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
        return verifier.verify(signatureBytes);
    }
}
