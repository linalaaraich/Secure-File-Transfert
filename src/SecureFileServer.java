import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class SecureFileServer {
    private static final int PORT = 8888;
    private static final String STORAGE_DIR = "received_files";
    private static final Map<String, String> USERS = new HashMap<>();
    private static final String AES_KEY = "MySecretKey12345";
    private static final ExecutorService threadPool = Executors.newCachedThreadPool();
    static {
        USERS.put("Lina", "password123");
        USERS.put("Safae", "password123");
        USERS.put("admin", "admin123");
        
        try {
            Files.createDirectories(Paths.get(STORAGE_DIR));
        } catch (IOException e) {
            System.err.println("Erreur création répertoire: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        System.out.println("=== SERVEUR DE TRANSFERT DE FICHIERS SÉCURISÉ ===");
        System.out.println("Port d'écoute: " + PORT);
        System.out.println("Répertoire de stockage: " + STORAGE_DIR);
        System.out.println("Utilisateurs autorisés: " + USERS.keySet());
        System.out.println("En attente de connexions...\n");
        
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[MAIN] Nouvelle connexion: " + clientSocket.getInetAddress());
                
                ClientTransferHandler handler = new ClientTransferHandler(clientSocket);
                threadPool.execute(handler);
            }
        } catch (IOException e) {
            System.err.println("Erreur serveur: " + e.getMessage());
        }
    }

    static class ClientTransferHandler implements Runnable {
        private final Socket clientSocket;
        private BufferedReader in;
        private PrintWriter out;
        private DataInputStream dataIn;
        private String clientId;
        
        public ClientTransferHandler(Socket socket) {
            this.clientSocket = socket;
            this.clientId = socket.getInetAddress().toString();
        }
        
        @Override
        public void run() {
            try {
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                dataIn = new DataInputStream(clientSocket.getInputStream());

                if (!handleAuthentication()) {
                    System.out.println("[" + clientId + "] Authentification échouée");
                    return;
                }
                FileMetadata metadata = handleNegotiation();
                if (metadata == null) {
                    System.out.println("[" + clientId + "] Négociation échouée");
                    return;
                }
                boolean success = handleFileTransfer(metadata);
                if (success) {
                    out.println("TRANSFER_SUCCESS");
                    System.out.println("[" + clientId + "] Transfert réussi: " + metadata.fileName);
                } else {
                    out.println("TRANSFER_FAIL");
                    System.out.println("[" + clientId + "] Transfert échoué");
                }
                
            } catch (Exception e) {
                System.err.println("[" + clientId + "] Erreur: " + e.getMessage());
                e.printStackTrace();
            } finally {
                closeConnection();
            }
        }

        private boolean handleAuthentication() throws IOException {
            System.out.println("[" + clientId + "] Phase 1: Authentification");
            
            String credentials = in.readLine();
            String[] parts = credentials.split(":");
            
            if (parts.length != 2) {
                out.println("AUTH_FAIL");
                return false;
            }
            
            String login = parts[0];
            String password = parts[1];
            
            if (USERS.containsKey(login) && USERS.get(login).equals(password)) {
                out.println("AUTH_OK");
                clientId = login + "@" + clientSocket.getInetAddress();
                System.out.println("[" + clientId + "] Authentification réussie");
                return true;
            } else {
                out.println("AUTH_FAIL");
                return false;
            }
        }

        private FileMetadata handleNegotiation() throws IOException {
            System.out.println("[" + clientId + "] Phase 2: Négociation");
            String metadataLine = in.readLine();
            String[] parts = metadataLine.split("\\|");
            if (parts.length != 3) {
                out.println("NEGOTIATION_FAIL");
                return null;
            }
            FileMetadata metadata = new FileMetadata();
            metadata.fileName = parts[0];
            metadata.fileSize = Long.parseLong(parts[1]);
            metadata.sha256Hash = parts[2];
            System.out.println("[" + clientId + "] Métadonnées reçues:");
            System.out.println("  - Fichier: " + metadata.fileName);
            System.out.println("  - Taille: " + metadata.fileSize + " bytes");
            System.out.println("  - Hash SHA-256: " + metadata.sha256Hash);
            out.println("READY_FOR_TRANSFER");
            return metadata;
        }

        private boolean handleFileTransfer(FileMetadata metadata) throws Exception {
            System.out.println("[" + clientId + "] Phase 3: Transfert et vérification");
            int encryptedSize = dataIn.readInt();
            System.out.println("[" + clientId + "] Taille du fichier chiffré: " + encryptedSize + " bytes");
            byte[] encryptedData = new byte[encryptedSize];
            dataIn.readFully(encryptedData);
            System.out.println("[" + clientId + "] Fichier chiffré reçu");
            byte[] decryptedData = decryptFile(encryptedData);
            if (decryptedData == null) {
                System.out.println("[" + clientId + "] Erreur de déchiffrement");
                return false;
            }
            System.out.println("[" + clientId + "] Fichier déchiffré avec succès");
            String calculatedHash = calculateSHA256(decryptedData);
            System.out.println("[" + clientId + "] Hash calculé: " + calculatedHash);
            System.out.println("[" + clientId + "] Hash attendu: " + metadata.sha256Hash);
            if (!calculatedHash.equals(metadata.sha256Hash)) {
                System.out.println("[" + clientId + "] Erreur d'intégrité: les hash ne correspondent pas");
                return false;
            }
            String safeFileName = sanitizeFileName(metadata.fileName);
            Path filePath = Paths.get(STORAGE_DIR, System.currentTimeMillis() + "_" + safeFileName);
            Files.write(filePath, decryptedData);
            System.out.println("[" + clientId + "] Fichier sauvegardé: " + filePath);
            
            return true;
        }
        private byte[] decryptFile(byte[] encryptedData) {
            try {
                byte[] keyBytes = AES_KEY.getBytes("UTF-8");
                keyBytes = Arrays.copyOf(keyBytes, 16); // AES-128
                SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
                
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                
                return cipher.doFinal(encryptedData);
            } catch (Exception e) {
                System.err.println("[" + clientId + "] Erreur de déchiffrement: " + e.getMessage());
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

        private String sanitizeFileName(String fileName) {
            return fileName.replaceAll("[^a-zA-Z0-9._-]", "_");
        }

        private void closeConnection() {
            try {
                if (in != null) in.close();
                if (out != null) out.close();
                if (dataIn != null) dataIn.close();
                if (clientSocket != null && !clientSocket.isClosed()) {
                    clientSocket.close();
                }
                System.out.println("[" + clientId + "] Connexion fermée");
            } catch (IOException e) {
                System.err.println("[" + clientId + "] Erreur fermeture: " + e.getMessage());
            }
        }
    }

    static class FileMetadata {
        String fileName;
        long fileSize;
        String sha256Hash;
    }
}
