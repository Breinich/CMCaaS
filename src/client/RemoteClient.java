import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class RemoteClient {
    private SecretKey aesKey;
    private byte[] nonce;

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

    public void run(String host, int port, String username, String password, String filename) throws Exception {
        HttpClient httpClient = HttpClient.newHttpClient();
        String credentials = Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));

        final String baseUrl = "http://" + host + ":" + port + "/verifier";

        // Register if needed
        httpClient.send(HttpRequest.newBuilder(URI.create(baseUrl + "/register"))
            .POST(HttpRequest.BodyPublishers.ofString("username=" + username + "&password=" + password))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .build(),
            HttpResponse.BodyHandlers.ofString()
        );

        // Authenticate and get enclave public key
        PublicKey enclavePub;
        String enclavePubB64 = httpClient.send(
            java.net.http.HttpRequest.newBuilder()
                .uri(new java.net.URI(baseUrl + "/init"))
                .header("Authorization", "Basic " + credentials)
                .GET()
                .build(),
            java.net.http.HttpResponse.BodyHandlers.ofString()
        ).body();
        byte[] enclavePubBytes = Base64.getDecoder().decode(enclavePubB64);
        KeyFactory kf = KeyFactory.getInstance("EC");
        enclavePub = kf.generatePublic(new X509EncodedKeySpec(enclavePubBytes));

        // Send payload and file for processing and receive encrypted result
        String payloadB64 = encryptKeyMaterials(enclavePub);
        Path encFilePath = Paths.get(encryptFile(filename));

        byte[] fileBytes = Files.readAllBytes(encFilePath);

        // Build multipart request
        String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();
        String LINE_FEED = "\r\n";
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(byteArrayOutputStream, StandardCharsets.UTF_8), true);

        // Add file part
        writer.append("--").append(boundary).append(LINE_FEED);
        writer.append("Content-Disposition: form-data; name=\"file\"; filename=\"")
                .append(String.valueOf(encFilePath.getFileName())).append("\"")
                .append(LINE_FEED);
        writer.append("Content-Type: application/octet-stream").append(LINE_FEED);
        writer.append(LINE_FEED).flush();
        byteArrayOutputStream.write(fileBytes);
        byteArrayOutputStream.flush();
        writer.append(LINE_FEED).flush();

        // Add clientData part
        writer.append("--").append(boundary).append(LINE_FEED);
        writer.append("Content-Disposition: form-data; name=\"clientData\"").append(LINE_FEED);
        writer.append(LINE_FEED).append(payloadB64).append(LINE_FEED).flush();
        writer.append("--").append(boundary).append("--").append(LINE_FEED).flush();

        // Add publicKey part
        writer.append("--").append(boundary).append(LINE_FEED);
        writer.append("Content-Disposition: form-data; name=\"publicKey\"").append(LINE_FEED);
        writer.append(LINE_FEED).append(enclavePubB64).append(LINE_FEED).flush();
        writer.append("--").append(boundary).append("--").append(LINE_FEED).flush();

        byte[] multipartBody = byteArrayOutputStream.toByteArray();

        HttpResponse<byte[]> response = httpClient.send(
            java.net.http.HttpRequest.newBuilder()
                .uri(new java.net.URI(baseUrl + "/process"))
                .header("Authorization", "Basic " + credentials)
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(multipartBody))
                .build(),
            java.net.http.HttpResponse.BodyHandlers.ofByteArray()
        );

        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to process file: " + new String(response.body(), StandardCharsets.UTF_8));
        }

        // Save the encrypted response to a file
        String encResponseFilename = "enc_response_" + new File(filename).getName();
        Files.write(Paths.get(encResponseFilename), response.body());

        // Decrypt the response file
        String decryptedFilename = decryptFile(encResponseFilename);
        System.out.println("Decrypted result from enclave: " + decryptedFilename);
        System.out.flush();
    }

    private String decryptFile(String filename) {
        try {
            // Read file
            byte[] fileData = Files.readAllBytes(Paths.get(filename));

            // Decrypt with AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
            byte[] decData = cipher.doFinal(fileData);

            // Save the decrypted file
            String decFilename = "dec_" + new File(filename).getName();
            Files.write(Paths.get(decFilename), decData);
            return decFilename;
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Failed to decrypt file: " + e.getMessage(), e);
        }
    }

    private String encryptFile(String filename) {
        try {
            // Read file
            byte[] fileData = Files.readAllBytes(Paths.get(filename));

            // Encrypt with AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            byte[] encData = cipher.doFinal(fileData);

            // Save the encrypted file
            String encFilename = "enc_" + new File(filename).getName();
            Files.write(Paths.get(encFilename), encData);
            return encFilename;
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt file: " + e.getMessage(), e);
        }
    }

    public static void main(String[] args) throws Exception {

        Console cnsl = System.console();

        if (cnsl == null) {
            System.out.println("No console available");
            System.out.flush();
            return;
        }

        String host = cnsl.readLine("Enter service host (default: localhost): ");
        if (host == null || host.isEmpty()) {
            host = "localhost";
        }
        int port = Integer.parseInt(cnsl.readLine("Enter service port (default: 8080): ", "8080"));
        String userName = cnsl.readLine("Enter username: ");
        String password = new String(cnsl.readPassword("Enter password: "));
        String filename = cnsl.readLine("Enter filename to process: ");

        RemoteClient client = new RemoteClient();
        client.run(host, port, userName, password, filename);
    }
}

