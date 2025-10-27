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

    private static HttpRequest.BodyPublisher ofMultipartData(Map<Object, Object> data, String boundary) throws Exception {
        var byteArrays = new java.util.ArrayList<byte[]>();
        String LINE_FEED = "\r\n";

        for (Map.Entry<Object, Object> entry : data.entrySet()) {
            byteArrays.add(("--" + boundary + LINE_FEED).getBytes(StandardCharsets.UTF_8));
            if (entry.getValue() instanceof Path) {
                Path path = (Path) entry.getValue();
                String mimeType = Files.probeContentType(path);
                byteArrays.add(("Content-Disposition: form-data; name=\"" + entry.getKey() +
                        "\"; filename=\"" + path.getFileName() + "\"" + LINE_FEED).getBytes(StandardCharsets.UTF_8));
                byteArrays.add(("Content-Type: " + (mimeType != null ? mimeType : "application/octet-stream") + LINE_FEED).getBytes(StandardCharsets.UTF_8));
                byteArrays.add(LINE_FEED.getBytes(StandardCharsets.UTF_8));
                byteArrays.add(Files.readAllBytes(path));
                byteArrays.add(LINE_FEED.getBytes(StandardCharsets.UTF_8));
            } else {
                byteArrays.add(("Content-Disposition: form-data; name=\"" + entry.getKey() + "\"" + LINE_FEED).getBytes(StandardCharsets.UTF_8));
                byteArrays.add(LINE_FEED.getBytes(StandardCharsets.UTF_8));
                byteArrays.add(entry.getValue().toString().getBytes(StandardCharsets.UTF_8));
                byteArrays.add(LINE_FEED.getBytes(StandardCharsets.UTF_8));
            }
        }

        byteArrays.add(("--" + boundary + "--" + LINE_FEED).getBytes(StandardCharsets.UTF_8));
        return HttpRequest.BodyPublishers.ofByteArrays(byteArrays);
    }

    public void run(String host, int port, String username, String password, String filename) {
        HttpClient httpClient = HttpClient.newHttpClient();
        String credentials = Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));

        final String baseUrl = "http://" + host + ":" + port + "/verifier";

        try {
            String jsonPayload = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);

            // Register if needed
           HttpRequest regRequest = HttpRequest.newBuilder(URI.create(baseUrl + "/register"))
                   .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                   .header("Content-Type", "application/json")
                   .build();

           regRequest.headers().map().forEach((k, v) -> System.out.println("Request header: " + k + " = " + String.join(",", v)));
           httpClient.send(regRequest, HttpResponse.BodyHandlers.ofString());

        } catch (Exception e) {
            // Ignore registration errors (e.g. user already exists)
        }

        String enclavePubB64;
        PublicKey enclavePub;
        try {
            // Authenticate and get enclave public key
            java.net.http.HttpRequest initRequest = java.net.http.HttpRequest.newBuilder()
                    .uri(new java.net.URI(baseUrl + "/init"))
                    .header("Authorization", "Basic " + credentials)
                    .GET()
                    .build();

            initRequest.headers().map().forEach((k, v) -> System.out.println("Request header: " + k + " = " + String.join(",", v)));

            java.net.http.HttpResponse<String> initResponse = httpClient.send(initRequest, java.net.http.HttpResponse.BodyHandlers.ofString());

            enclavePubB64 = initResponse.body();

            System.out.println("Received Enclave Public Key: " + enclavePubB64);

            byte[] enclavePubBytes = Base64.getDecoder().decode(enclavePubB64);
            KeyFactory kf = KeyFactory.getInstance("EC");
            enclavePub = kf.generatePublic(new X509EncodedKeySpec(enclavePubBytes));
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize connection: " + e.getMessage(), e);
        }

        Path encFilePath;
        String payloadB64;
        try {
            payloadB64 = encryptKeyMaterials(enclavePub);
            encFilePath = Paths.get(encryptFile(filename));
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt payload: " + e.getMessage(), e);
        }

        HttpResponse<String> response;
        try {

            Map<Object, Object> data = new HashMap<>();
            data.put("file", encFilePath);
            data.put("clientData", payloadB64);
            data.put("publicKey", enclavePubB64);
            String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();

            // start verification
            response = httpClient.send(
                    java.net.http.HttpRequest.newBuilder()
                            .uri(new java.net.URI(baseUrl + "/process"))
                            .header("Authorization", "Basic " + credentials)
                            .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                            .POST(ofMultipartData(data, boundary))
                            .build(),
                    HttpResponse.BodyHandlers.ofString()
            );

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to start the verification: " + response.body());
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to send verification request: " + e.getMessage(), e);
        }

        System.out.println("Verification job started. Polling for results...");

        HttpResponse<byte[]> pollResp;
        boolean completed = false;
        Path outputFile = Paths.get("enc_response_" + new File(filename).getName());

        try {
            while (!completed) {
                Thread.sleep(10000); // wait 10 seconds between polls

                HttpRequest pollRequest = HttpRequest.newBuilder()
                        .uri(new URI(baseUrl + "/process?publicKey=" + enclavePubB64))
                        .header("Authorization", "Basic " + credentials)
                        .GET()
                        .build();

                pollResp = httpClient.send(pollRequest, HttpResponse.BodyHandlers.ofByteArray());

                if (pollResp.statusCode() == 200) {
                    System.out.println("Result ready, downloading...");
                    Files.write(outputFile, pollResp.body());
                    completed = true;
                } else {
                    System.out.println("Result not ready yet (status " + pollResp.statusCode() + ")");
                }
            }
        } catch (Exception e){
            System.err.println("Failed to download results: " + e.getMessage());
        }


        try {
            // Decrypt the response file
            String decryptedFilename = decryptFile(outputFile.toString());
            System.out.println("Decrypted result from enclave: " + decryptedFilename);
        } catch (Exception e) {
            throw new RuntimeException("Error during run: " + e.getMessage(), e);
        }
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

    public static void main(String[] args) {

        Console cnsl = System.console();

        if (cnsl == null) {
            System.out.println("No console available");
            return;
        }

        String host = cnsl.readLine("Enter service host (default: localhost): ");
        if (host == null || host.isEmpty()) {
            host = "localhost";
        }
        String port = cnsl.readLine("Enter service port (default: 8080): ");
        if (port == null || port.isEmpty()) {
            port = "8080";
        }
        String userName = cnsl.readLine("Enter username (default: test): ");
        if (userName == null || userName.isEmpty()) {
            userName = "test";
        }

        String password = new String(cnsl.readPassword("Enter password: "));
        String filename = cnsl.readLine("Enter filename to process (default: test.zip): ");
        if (filename == null || filename.isEmpty()) {
            filename = "test.zip";
        }

        RemoteClient client = new RemoteClient();
        client.run(host, Integer.parseInt(port), userName, password, filename);
    }
}

