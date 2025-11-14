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
    
    /**
     * Initialize Diffie-Hellman parameters and generate key pair
     */
    public DiffieHellmanKeyExchange() throws Exception {
        // Generate DH parameters
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance(DH_ALGORITHM);
        paramGen.init(DH_KEY_SIZE);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhParamSpec = params.getParameterSpec(DHParameterSpec.class);
        
        // Generate DH key pair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyPairGen.initialize(dhParamSpec);
        dhKeyPair = keyPairGen.generateKeyPair();
        
        // Initialize key agreement
        keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM);
        keyAgreement.init(dhKeyPair.getPrivate());
    }
    
    /**
     * Initialize with pre-generated parameters (for faster initialization)
     */
    public DiffieHellmanKeyExchange(DHParameterSpec dhParamSpec) throws Exception {
        // Generate DH key pair with provided parameters
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyPairGen.initialize(dhParamSpec);
        dhKeyPair = keyPairGen.generateKeyPair();
        
        // Initialize key agreement
        keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM);
        keyAgreement.init(dhKeyPair.getPrivate());
    }
    
    /**
     * Get the public key to send to the other party
     */
    public PublicKey getPublicKey() {
        return dhKeyPair.getPublic();
    }
    
    /**
     * Get the public key encoded as Base64 string for transmission
     */
    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(dhKeyPair.getPublic().getEncoded());
    }
    
    /**
     * Process the other party's public key and generate shared secret
     */
    public void processOtherPartyPublicKey(PublicKey otherPublicKey) throws Exception {
        keyAgreement.doPhase(otherPublicKey, true);
        sharedSecret = keyAgreement.generateSecret();
        
        // Generate AES key from shared secret
        generateAESKey();
    }
    
    /**
     * Process the other party's public key from Base64 string
     */
    public void processOtherPartyPublicKeyBase64(String publicKeyBase64) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        
        // Reconstruct public key
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(DH_ALGORITHM);
        PublicKey otherPublicKey = keyFactory.generatePublic(keySpec);
        
        processOtherPartyPublicKey(otherPublicKey);
    }
    
    /**
     * Generate AES key from shared secret
     */
    private void generateAESKey() throws Exception {
        // Use SHA-256 to derive a 256-bit AES key from the shared secret
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(sharedSecret);
        
        // Use first 16 bytes for AES-128 (or 32 bytes for AES-256)
        byte[] aesKeyBytes = new byte[16]; // 128-bit AES
        System.arraycopy(keyBytes, 0, aesKeyBytes, 0, 16);
        
        aesKey = new SecretKeySpec(aesKeyBytes, AES_ALGORITHM);
    }
    
    /**
     * Get the generated AES key
     */
    public SecretKey getAESKey() {
        return aesKey;
    }
    
    /**
     * Get the AES key as Base64 string (for debugging/logging only!)
     */
    public String getAESKeyBase64() {
        if (aesKey != null) {
            return Base64.getEncoder().encodeToString(aesKey.getEncoded());
        }
        return null;
    }
    
    /**
     * Encrypt data using the established AES key
     */
    public byte[] encrypt(byte[] plaintext) throws Exception {
        if (aesKey == null) {
            throw new IllegalStateException("AES key not yet established");
        }
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return cipher.doFinal(plaintext);
    }
    
    /**
     * Decrypt data using the established AES key
     */
    public byte[] decrypt(byte[] ciphertext) throws Exception {
        if (aesKey == null) {
            throw new IllegalStateException("AES key not yet established");
        }
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return cipher.doFinal(ciphertext);
    }
    
    /**
     * Get standard DH parameters for reuse (to speed up initialization)
     */
    public static DHParameterSpec getStandardDHParams() {
        // Standard 2048-bit MODP Group from RFC 3526
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
