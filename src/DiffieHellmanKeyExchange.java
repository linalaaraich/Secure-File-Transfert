import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

/**
 * Utility class for Diffie-Hellman key exchange
 * This allows client and server to establish a shared secret key
 * without transmitting it directly over the network
 */
public class DiffieHellmanKeyExchange {
    
    private static final String DH_ALGORITHM = "DH";
    private static final String AES_ALGORITHM = "AES";
    private static final int DH_KEY_SIZE = 2048;
    
    private KeyPair dhKeyPair;
    private KeyAgreement keyAgreement;
    private byte[] sharedSecret;
    private SecretKey aesKey;
    

    public DiffieHellmanKeyExchange() throws Exception {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance(DH_ALGORITHM);
        paramGen.init(DH_KEY_SIZE);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhParamSpec = params.getParameterSpec(DHParameterSpec.class);
        
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyPairGen.initialize(dhParamSpec);
        dhKeyPair = keyPairGen.generateKeyPair();
        
        keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM);
        keyAgreement.init(dhKeyPair.getPrivate());
    }
    

    public DiffieHellmanKeyExchange(DHParameterSpec dhParamSpec) throws Exception {
        // Generate DH key pair with provided parameters
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyPairGen.initialize(dhParamSpec);
        dhKeyPair = keyPairGen.generateKeyPair();
        
        // Initialize key agreement
        keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM);
        keyAgreement.init(dhKeyPair.getPrivate());
    }
    

    public PublicKey getPublicKey() {
        return dhKeyPair.getPublic();
    }
    

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(dhKeyPair.getPublic().getEncoded());
    }
    

    public void processOtherPartyPublicKey(PublicKey otherPublicKey) throws Exception {
        keyAgreement.doPhase(otherPublicKey, true);
        sharedSecret = keyAgreement.generateSecret();
        
        generateAESKey();
    }
    

    public void processOtherPartyPublicKeyBase64(String publicKeyBase64) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(DH_ALGORITHM);
        PublicKey otherPublicKey = keyFactory.generatePublic(keySpec);
        
        processOtherPartyPublicKey(otherPublicKey);
    }
    

    private void generateAESKey() throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(sharedSecret);
        
        byte[] aesKeyBytes = new byte[16]; // 128-bit AES
        System.arraycopy(keyBytes, 0, aesKeyBytes, 0, 16);
        
        aesKey = new SecretKeySpec(aesKeyBytes, AES_ALGORITHM);
    }
    

    public SecretKey getAESKey() {
        return aesKey;
    }

    public String getAESKeyBase64() {
        if (aesKey != null) {
            return Base64.getEncoder().encodeToString(aesKey.getEncoded());
        }
        return null;
    }

    public byte[] encrypt(byte[] plaintext) throws Exception {
        if (aesKey == null) {
            throw new IllegalStateException("AES key not yet established");
        }
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return cipher.doFinal(plaintext);
    }
    

    public byte[] decrypt(byte[] ciphertext) throws Exception {
        if (aesKey == null) {
            throw new IllegalStateException("AES key not yet established");
        }
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return cipher.doFinal(ciphertext);
    }
    

    public static DHParameterSpec getStandardDHParams() {

        String primeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                         "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                         "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                         "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                         "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                         "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                         "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                         "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                         "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                         "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                         "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
        
        try {
            BigInteger prime = new BigInteger(primeHex, 16);
            BigInteger generator = BigInteger.valueOf(2);
            return new DHParameterSpec(prime, generator);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
