import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class SecureFileClient {
    
    private static final String AES_KEY = "MySecretKey12345"; // 16 bytes  AES-128
    
    private String serverAddress;
    private int serverPort;
    private String username;
    private String password;
    private String filePath;
    
    // Flux
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    private DataOutputStream dataOut;
    
    public SecureFileClient(String serverAddress, int serverPort, String username, String password, String filePath) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.username = username;
        this.password = password;
        this.filePath = filePath;
    }

    public void transfer() {
        System.out.println("=== CLIENT DE TRANSFERT DE FICHIERS SÉCURISÉ ===");
        System.out.println("Serveur: " + serverAddress + ":" + serverPort);
        System.out.println("Utilisateur: " + username);
        System.out.println("Fichier source: " + filePath);
        System.out.println();
        
        try {
            connect();
            if (!authenticate()) {
                System.err.println("Authentification échouée!");
                return;
            }
            
            File file = new File(filePath);
            if (!file.exists() || !file.isFile()) {
                System.err.println("Fichier introuvable: " + filePath);
                return;
            }
            
            byte[] fileContent = Files.readAllBytes(file.toPath());
            System.out.println("Fichier lu: " + fileContent.length + " bytes");
            
            String sha256Hash = calculateSHA256(fileContent);
            System.out.println("Hash SHA-256 calculé: " + sha256Hash);
            
            byte[] encryptedContent = encryptFile(fileContent);
            if (encryptedContent == null) {
                System.err.println("Erreur de chiffrement!");
                return;
            }
            System.out.println("Fichier chiffré: " + encryptedContent.length + " bytes");
            
            if (!negotiate(file.getName(), fileContent.length, sha256Hash)) {
                System.err.println("Négociation échouée!");
                return;
            }
            if (transferFile(encryptedContent)) {
                System.out.println("\n✓ TRANSFERT TERMINÉ AVEC SUCCÈS!");
            } else {
                System.err.println("\n✗ ÉCHEC DU TRANSFERT!");
            }
            
        } catch (Exception e) {
            System.err.println("Erreur: " + e.getMessage());
            e.printStackTrace();
        } finally {
            disconnect();
        }
    }

    private void connect() throws IOException {
        System.out.println("Connexion au serveur...");
        socket = new Socket(serverAddress, serverPort);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
        dataOut = new DataOutputStream(socket.getOutputStream());
        System.out.println("Connecté au serveur!");
    }

    private boolean authenticate() throws IOException {
        System.out.println("\n--- Phase 1: Authentification ---");
        String credentials = username + ":" + password;
        out.println(credentials);
        System.out.println("Identifiants envoyés");
        String response = in.readLine();
        System.out.println("Réponse serveur: " + response);
        
        return "AUTH_OK".equals(response);
    }
    private boolean negotiate(String fileName, long fileSize, String sha256Hash) throws IOException {
        System.out.println("\n--- Phase 2: Négociation ---");
        
        String metadata = fileName + "|" + fileSize + "|" + sha256Hash;
        out.println(metadata);
        System.out.println("Métadonnées envoyées:");
        System.out.println("  - Nom: " + fileName);
        System.out.println("  - Taille: " + fileSize + " bytes");
        System.out.println("  - Hash: " + sha256Hash);
        
        String response = in.readLine();
        System.out.println("Réponse serveur: " + response);
        
        return "READY_FOR_TRANSFER".equals(response);
    }

    private boolean transferFile(byte[] encryptedContent) throws IOException {
        System.out.println("\n--- Phase 3: Transfert ---");
        
        dataOut.writeInt(encryptedContent.length);
        System.out.println("Taille envoyée: " + encryptedContent.length + " bytes");
        
        dataOut.write(encryptedContent);
        dataOut.flush();
        System.out.println("Fichier chiffré envoyé");
        
        String response = in.readLine();
        System.out.println("Réponse serveur: " + response);
        
        return "TRANSFER_SUCCESS".equals(response);
    }

    private byte[] encryptFile(byte[] fileContent) {
        try {
            byte[] keyBytes = AES_KEY.getBytes("UTF-8");
            keyBytes = Arrays.copyOf(keyBytes, 16); // AES-128
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            return cipher.doFinal(fileContent);
        } catch (Exception e) {
            System.err.println("Erreur de chiffrement: " + e.getMessage());
            return null;
        }
    }

    private String calculateSHA256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private void disconnect() {
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (dataOut != null) dataOut.close();
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            System.out.println("\nConnexion fermée.");
        } catch (IOException e) {
            System.err.println("Erreur fermeture: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        int serverPort =  8888 ;
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== Configuration du transfert ===");
        System.out.print("Adresse IP du serveur: ");
        String serverAddress = scanner.nextLine();
        System.out.print("Nom d'utilisateur: ");
        String username = scanner.nextLine();
        System.out.print("Mot de passe: ");
        String password = scanner.nextLine();
        System.out.print("Chemin du fichier à envoyer: ");
        String filePath = scanner.nextLine();
        System.out.println();
        SecureFileClient client = new SecureFileClient(
            serverAddress, serverPort, username, password, filePath
        );
        client.transfer();
        
        scanner.close();
    }
}
