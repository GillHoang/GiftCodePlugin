package vn.hanh.hehe.crypto;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class Ed25519 {
    private Ed25519() {}

    public static PublicKey loadPublicKeyFromPEM(String pem) throws Exception {
        String sanitized = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(sanitized);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("Ed25519").generatePublic(spec);
    }

    public static boolean verify(String rawJsonWithoutSignature, String signatureB64, PublicKey pub) {
        try {
            if (signatureB64 == null || signatureB64.isEmpty()) return false;
            byte[] sig = Base64.getDecoder().decode(signatureB64);
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(pub);
            s.update(rawJsonWithoutSignature.getBytes(StandardCharsets.UTF_8));
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }
}
