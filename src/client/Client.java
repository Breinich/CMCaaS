import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class Client {
    private SecretKey aesKey;
    private byte[] nonce;

    private static final String SHARED_DIR = "occlum_verifier_5001";

    /**
     * HKDF-SHA256 implementation
     * @param salt optional salt
     * @param ikm input keying material
     * @param info optional context and application-specific information
     * @param outputLen output length in bytes
     * @return derived key
     */
    private static byte[] hkdfSha256(byte[] salt, byte[] ikm, byte[] info, int outputLen) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        if (salt == null || salt.length == 0) salt = new byte[32];
        SecretKeySpec saltKey = new SecretKeySpec(salt, "HmacSHA256");
        hmac.init(saltKey);
        byte[] prk = hmac.doFinal(ikm);

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
     * @param priv Private key
     * @param peerPub Public key
     * @return Derived AES key
     */
    private SecretKey deriveAesKey(PrivateKey priv, PublicKey peerPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(priv);
        ka.doPhase(peerPub, true);
        byte[] sharedSecret = ka.generateSecret();

        byte[] info = "enclave-ecdh-aes-256-gcm".getBytes(StandardCharsets.UTF_8);
        byte[] aesKeyBytes = hkdfSha256(null, sharedSecret, info, 32);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    public String encryptKeyMaterials(PublicKey enclavePub) throws Exception {

        // Generate ephemeral client keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey clientPriv = kp.getPrivate();
        PublicKey clientPub = kp.getPublic();

        // Derive an AES key and generate nonce
        aesKey = deriveAesKey(clientPriv, enclavePub);
        nonce = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(nonce);

        byte[] clientPubBytes = clientPub.getEncoded();

        // Frame: [4 clientPubLen][clientPub][4 nonceLen][nonce]
        ByteBuffer buf = ByteBuffer.allocate(4 + clientPubBytes.length + 4 + nonce.length);
        buf.putInt(clientPubBytes.length);
        buf.put(clientPubBytes);
        buf.putInt(nonce.length);
        buf.put(nonce);

        return Base64.getEncoder().encodeToString(buf.array());
    }

    private PublicKey init(String host, int port) {
        try (Socket s = new Socket(host, port)) {
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());

            out.writeUTF("init");
            out.flush();

            // Step 1: read enclave public key
            String enclavePubB64 = in.readUTF();
            byte[] enclavePubBytes = Base64.getDecoder().decode(enclavePubB64);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey enclavePub = kf.generatePublic(new X509EncodedKeySpec(enclavePubBytes));
            System.out.println("Received Enclave Public Key: " + enclavePubB64);
            System.out.flush();
            return enclavePub;
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to initialize connection: " + e.getMessage(), e);
        }
    }

    private void process(String host, int port, String filename, PublicKey enclavePub) {
        try (Socket s = new Socket(host, port)) {
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());

            out.writeUTF("process");
            out.flush();

            // Step 2: build and send payload (clientPub + nonce)
            String payloadB64 = encryptKeyMaterials(enclavePub);
            out.writeUTF(payloadB64);
            out.flush();
            System.out.println("Sent encrypted payload: " + payloadB64);
            System.out.flush();

            // Step 3: encrypt the file and send to enclave
            String encryptedFilename = encryptFile(filename);
            out.writeUTF(encryptedFilename);
            out.flush();
            System.out.println("Sent filename: " + encryptedFilename);
            System.out.flush();

            // Step 4: receive encrypted output filename
            String encryptedResult = in.readUTF();
            System.out.println("Encrypted output filename received: " + encryptedResult);
            System.out.flush();

            // Step 5: optionally decrypt response
            String decryptedFilename = decryptFile(encryptedResult);
            System.out.println("Decrypted response from enclave: " + decryptedFilename);
            System.out.flush();
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to process file: " + e.getMessage(), e);
        }

    }

    public void run(String host, int port, String filename) {
        PublicKey enclavePub = init(host, port);

        process(host, port, filename, enclavePub);
    }

    private String decryptFile(String filename) {
        try {
            // Read file
            byte[] fileData = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(SHARED_DIR, filename));

            // Decrypt with AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
            byte[] decData = cipher.doFinal(fileData);

            // Save the decrypted file
            String decFilename = "dec_" + new File(filename).getName();
            java.nio.file.Files.write(java.nio.file.Paths.get(SHARED_DIR, decFilename), decData);
            return decFilename;
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Failed to decrypt file: " + e.getMessage(), e);
        }
    }

    private String encryptFile(String filename) {
        try {
            // Read file
            byte[] fileData = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename));

            // Encrypt with AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            byte[] encData = cipher.doFinal(fileData);

            // Save the encrypted file
            String encFilename = "enc_" + new File(filename).getName();
            java.nio.file.Files.write(java.nio.file.Paths.get(SHARED_DIR, encFilename), encData);
            return encFilename;
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt file: " + e.getMessage(), e);
        }
    }

    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: java Client <host> <port> <filename>");
            System.exit(1);
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String filename = args[2];

        Client client = new Client();
        client.run(host, port, filename);
    }
}

