import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * enclave.RobustEnclaveApp
 */
public class VerifierRunner {
    private static final String SHARED_DIR = "/host";

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private byte[] nonce;
    private SecretKey aesKey;
    private boolean stop = false;

    /**
     * Generate EC key pair (secp256r1)
     */
    private void generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = keyGen.generateKeyPair();
        privateKey = kp.getPrivate();
        publicKey = kp.getPublic();
    }

    /**
     * Export public key as Base64 (X.509 encoded)
     * @return Base64 string
     */
    private String exportPublicKey() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * HKDF-SHA256 implementation
     * @param salt optional salt
     * @param ikm input keying material
     * @param info optional context and application-specific information
     * @param outputLen output length in bytes
     * @return derived key
     */
    private static byte[] hkdfSha256(byte[] salt, byte[] ikm, byte[] info, int outputLen) throws Exception {
        // Extract
        Mac hmac = Mac.getInstance("HmacSHA256");
        if (salt == null || salt.length == 0) {
            salt = new byte[32]; // zeros
        }
        SecretKeySpec saltKey = new SecretKeySpec(salt, "HmacSHA256");
        hmac.init(saltKey);
        byte[] prk = hmac.doFinal(ikm);

        // Expand
        int hashLen = 32;
        int n = (outputLen + hashLen - 1) / hashLen;
        byte[] okm = new byte[0];
        byte[] t = new byte[0];
        for (int i = 1; i <= n; i++) {
            hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
            hmac.update(t);
            if (info != null) hmac.update(info);
            hmac.update((byte) i);
            t = hmac.doFinal();
            okm = concat(okm, t);
        }
        byte[] out = new byte[outputLen];
        System.arraycopy(okm, 0, out, 0, outputLen);
        return out;
    }

    /**
     * Concatenate two byte arrays
     * @param a first byte array
     * @param b second byte array
     * @return concatenated byte array
     */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    /**
     * Derive an AES key from ECDH shared secret
     * @param peerPub the client's public key
     * @return derived AES key
     */
    private SecretKey deriveAesKey(PublicKey peerPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(peerPub, true);
        byte[] sharedSecret = ka.generateSecret();

        // HKDF with optional info (context string)
        byte[] info = "enclave-ecdh-aes-256-gcm".getBytes(StandardCharsets.UTF_8);
	    byte[] aesKeyBytes = hkdfSha256(null, sharedSecret, info, 32); // AES-256
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    /**
     * Unpack an encrypted payload and derive an AES key
     * @param encryptedMessageBase64 Base64-encoded encrypted payload
     */
    private void decryptPayload(String encryptedMessageBase64) throws Exception {
        byte[] payload = Base64.getDecoder().decode(encryptedMessageBase64);
        ByteBuffer buf = ByteBuffer.wrap(payload);

        // Read clientPubLen + clientPub
        int clientPubLen = buf.getInt();
        if (clientPubLen <= 0 || clientPubLen > buf.remaining()) throw new IllegalArgumentException("bad clientPubLen");
        byte[] clientPubBytes = new byte[clientPubLen];
        buf.get(clientPubBytes);

        // nonce
        int nonceLen = buf.getInt();
        if (nonceLen <= 0 || nonceLen > buf.remaining()) throw new IllegalArgumentException("bad nonceLen");
        nonce = new byte[nonceLen];
        buf.get(nonce);

        // Reconstruct the client's public key
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey clientPub = kf.generatePublic(new X509EncodedKeySpec(clientPubBytes));

        // Derive AES key
        aesKey = deriveAesKey(clientPub);
    }

    /**
     * Decrypt uploaded file
     * @param filename file name
     */
    private void decryptFile(String filename) throws Exception {
        // Decrypt AES-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        // Read encrypted file
        Path filePath = Paths.get(SHARED_DIR, filename);
        byte[] encFile = java.nio.file.Files.readAllBytes(filePath);
        // Decrypt
        byte[] decFile = cipher.doFinal(encFile);
        // Write the decrypted file
        java.nio.file.Files.write(filePath, decFile);

        System.out.println("Decrypted file: " + filename);
    }

    /**
     * Unzip the file and run the model checking
     * @param filename file name
     * @return output file name (zip)
     */
    private String processFile(String filename) {
        // TODO: process file (e.g. run model)
        return filename;
    }

    /**
     * Encrypt the output file
     * @param filename file name
     * @return encrypted file name
     */
    private String encryptResults(String filename) throws Exception {

        byte[] fileBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(SHARED_DIR, filename));

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);


        byte[] encFile = cipher.doFinal(fileBytes);
        String encryptedFilename = "enc_" + filename;

        java.nio.file.Files.write(java.nio.file.Paths.get(SHARED_DIR, encryptedFilename), encFile);

        System.out.println("Encrypted output file: " + encryptedFilename);
        return encryptedFilename;
    }

    private String verifyModel(String filename) throws Exception {
        if (!java.nio.file.Files.exists(java.nio.file.Paths.get(SHARED_DIR, filename))) {
            System.err.println("File not found: " + filename);
            throw new IllegalArgumentException("File not found");
        }
        if (!filename.endsWith(".zip"))
            throw new IllegalArgumentException("File must be a .zip file");
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\"))
            throw new IllegalArgumentException("Invalid filename");

        decryptFile(filename);

        String result_name = processFile(filename);

        return encryptResults(result_name);
    }

    public VerifierRunner(int port) throws Exception {
        generateKeyPair();

        try (ServerSocket server = new ServerSocket(port, 10, InetAddress.getByName("127.0.0.1"))) {
            System.out.println("Verifier enclave listening on 127.0.0.1:" + port);

            while(!stop) {
                Socket client = server.accept();
                Thread t = new Thread(() -> {
                    try {
                        handle(client);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    finally {
                        try {
                            client.close();
                        } catch (IOException ignored) {}
                    }
                });
                t.start();
            }
        }
    }

    private void handle(Socket s) throws Exception {
        DataInputStream in = new DataInputStream(s.getInputStream());
        DataOutputStream out = new DataOutputStream(s.getOutputStream());

        String command = in.readUTF();
        switch (command) {
            case "init":
                System.out.println("INIT_COMMAND_RECEIVED");

                // Step 1: send server public key first
                String pubB64 = exportPublicKey();
                out.writeUTF(pubB64);
                out.flush();
                System.out.println("PUBLIC_KEY_BASE64=" + pubB64);
                break;
            case "process":
                System.out.println("PROCESS_COMMAND_RECEIVED");

                // Step 2: receive encrypted payload from the client, the client's public key and the nonce
                String payloadB64 = in.readUTF();
                System.out.println("ENCRYPTED_PAYLOAD=" + payloadB64);
                if (payloadB64.trim().isEmpty()) {
                    throw new IllegalArgumentException("No encrypted payload received");
                }
                decryptPayload(payloadB64);

                // Now AES key and nonce are available
                // Step 3: receive filename to process
                String filename = in.readUTF();
                System.out.println("FILENAME=" + filename);
                if (filename.trim().isEmpty()) {
                    throw new IllegalArgumentException("No filename received");
                }
                String encrypted_result_name = verifyModel(filename);

                // Step 4: send back the encrypted output filename
                out.writeUTF(encrypted_result_name);
                out.flush();
                System.out.println("ENCRYPTED_OUTPUT_FILENAME=" + encrypted_result_name);
                stop = true;
                break;
            case "stop":
                System.out.println("STOP_COMMAND_RECEIVED");
                stop = true;
                break;
            default:
                System.out.println("Unknown command: " + command);
                break;
        }
        s.close();
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        new VerifierRunner(port);
    }
}

