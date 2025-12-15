import java.io.*;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class RemoteClient {
    private SecretKey aesKey;
    private byte[] nonceBinary;

    /**
     * HKDF-SHA256 implementation
     *
     * @param salt optional salt
     * @param ikm input keying material
     * @param info optional context and application-specific information
     * @param outputLen output length in bytes
     * @return derived key
     */
    private static byte[] hkdfSha256(byte[] salt, byte[] ikm, byte[] info, int outputLen)
            throws Exception {
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
     *
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
     *
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

    public String generateKeyMaterials(PublicKey enclavePub) throws Exception {

        // Generate ephemeral client keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey clientPriv = kp.getPrivate();
        PublicKey clientPub = kp.getPublic();

        // Derive an AES key and generate nonce
        aesKey = deriveAesKey(clientPriv, enclavePub);
        nonceBinary = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(nonceBinary);

        byte[] clientPubBytes = clientPub.getEncoded();

        // Frame: [4 clientPubLen][clientPub][4 nonceLen][nonce]
        ByteBuffer buf = ByteBuffer.allocate(4 + clientPubBytes.length + 4 + nonceBinary.length);
        buf.putInt(clientPubBytes.length);
        buf.put(clientPubBytes);
        buf.putInt(nonceBinary.length);
        buf.put(nonceBinary);

        return Base64.getEncoder().encodeToString(buf.array());
    }

    private static HttpRequest.BodyPublisher ofMultipartData(
            Map<Object, Object> data, String boundary) throws Exception {
        var byteArrays = new java.util.ArrayList<byte[]>();
        String LINE_FEED = "\r\n";

        for (Map.Entry<Object, Object> entry : data.entrySet()) {
            byteArrays.add(("--" + boundary + LINE_FEED).getBytes(StandardCharsets.UTF_8));
            if (entry.getValue() instanceof Path) {
                Path path = (Path) entry.getValue();
                String mimeType = Files.probeContentType(path);
                byteArrays.add(
                        ("Content-Disposition: form-data; name=\""
                                + entry.getKey()
                                + "\"; filename=\""
                                + path.getFileName()
                                + "\""
                                + LINE_FEED)
                                .getBytes(StandardCharsets.UTF_8));
                byteArrays.add(
                        ("Content-Type: "
                                + (mimeType != null ? mimeType : "application/octet-stream")
                                + LINE_FEED)
                                .getBytes(StandardCharsets.UTF_8));
                byteArrays.add(LINE_FEED.getBytes(StandardCharsets.UTF_8));
                byteArrays.add(Files.readAllBytes(path));
                byteArrays.add(LINE_FEED.getBytes(StandardCharsets.UTF_8));
            } else {
                byteArrays.add(
                        ("Content-Disposition: form-data; name=\"" + entry.getKey() + "\"" + LINE_FEED)
                                .getBytes(StandardCharsets.UTF_8));
                byteArrays.add(LINE_FEED.getBytes(StandardCharsets.UTF_8));
                byteArrays.add(entry.getValue().toString().getBytes(StandardCharsets.UTF_8));
                byteArrays.add(LINE_FEED.getBytes(StandardCharsets.UTF_8));
            }
        }

        byteArrays.add(("--" + boundary + "--" + LINE_FEED).getBytes(StandardCharsets.UTF_8));
        return HttpRequest.BodyPublishers.ofByteArrays(byteArrays);
    }

    /**
     * Register a new user
     * @param username The username of the new user
     * @param password The password of the new user
     * @param baseUrl The base URL of the server
     * @param httpClient The HTTP client to use for the request
     */
    private void register(String username, String password, String baseUrl, HttpClient httpClient) {
        try {
            String jsonPayload =
                    String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);

            // Register if needed
            HttpRequest regRequest =
                    HttpRequest.newBuilder(URI.create(baseUrl + "/register"))
                            .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                            .header("Content-Type", "application/json")
                            .build();

            regRequest
                    .headers()
                    .map()
                    .forEach(
                            (k, v) -> System.out.println("Request header: " + k + " = " + String.join(",", v)));
            httpClient.send(regRequest, HttpResponse.BodyHandlers.ofString());

        } catch (Exception e) {
            // Ignore registration errors (e.g. user already exists)
        }
    }

    /**
     * Initialize connection and get enclave public key
     * @param baseUrl The base URL of the server
     * @param credentials The credentials for authentication
     * @param httpClient The HTTP client to use for the request
     * @return The enclave public key
     */
    private PublicKey init(String baseUrl, String credentials, HttpClient httpClient) {
        try {
            // Authenticate and get enclave public key
            java.net.http.HttpRequest initRequest =
                    java.net.http.HttpRequest.newBuilder()
                            .uri(new java.net.URI(baseUrl + "/init"))
                            .header("Authorization", "Basic " + credentials)
                            .GET()
                            .build();

            initRequest
                    .headers()
                    .map()
                    .forEach(
                            (k, v) -> System.out.println("Request header: " + k + " = " + String.join(",", v)));

            java.net.http.HttpResponse<String> initResponse =
                    httpClient.send(initRequest, java.net.http.HttpResponse.BodyHandlers.ofString());

            String enclavePubB64 = initResponse.body();

            System.out.println("Received Enclave Public Key: " + enclavePubB64);

            byte[] enclavePubBytes = Base64.getDecoder().decode(enclavePubB64);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePublic(new X509EncodedKeySpec(enclavePubBytes));
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize connection: " + e.getMessage(), e);
        }
    }

    private void shakeHands(String baseUrl, String credentials, HttpClient httpClient, PublicKey enclavePub,
                            String enclavePubB64) {
        String payloadB64;
        try {
            payloadB64 = generateKeyMaterials(enclavePub);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key materials: " + e.getMessage(), e);
        }

        try {
            Map<Object, Object> data = new HashMap<>();
            data.put("clientData", payloadB64);
            data.put("publicKey", enclavePubB64);
            String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();

            java.net.http.HttpRequest agreeRequest =
                    java.net.http.HttpRequest.newBuilder()
                            .uri(new java.net.URI(baseUrl + "/agree"))
                            .header("Authorization", "Basic " + credentials)
                            .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                            .POST(ofMultipartData(data, boundary))
                            .build();

            java.net.http.HttpResponse<String> agreeResponse =
                    httpClient.send(agreeRequest, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (agreeResponse.statusCode() != 200) {
                throw new RuntimeException("Failed to shake hands with enclave: " + agreeResponse.body());
            }

            System.out.println("Successfully shook hands with the enclave.");
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to shake hands: " + e.getMessage(), e);
        }
    }

    private void verifyQuote(String quoteB64, String nonce) throws IOException, InterruptedException {
        File logFile = new File("docker_verifier_output.log");

        ProcessBuilder builder = new ProcessBuilder("docker", "run", "--device", "/dev/sgx_enclave", "--device", "/dev/sgx_provision", "--rm", "cmcaas-verifier:latest", quoteB64, nonce);;
        builder.redirectErrorStream(true);

        Process process = builder.start();

        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
             BufferedWriter fileWriter = new BufferedWriter(new FileWriter(logFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
                fileWriter.write(line);
                fileWriter.newLine();
            }
        } catch (Exception e) {
            throw new RuntimeException("Error reading process output", e);
        }

        int exitCode = process.waitFor();

        if (exitCode == 0) {
            System.out.println("Enclave quote verified successfully.");
        }
        else {
            String errorOutput = lines.isEmpty() ? "No output captured." : String.join("\n", lines);

            System.err.println("Verification Failed (Exit Code " + exitCode + "):\n" + errorOutput);
            throw new RuntimeException("Failed to verify quote. Exit Code: " + exitCode + ". Output:\n" + errorOutput);
        }
    }

    private void attestEnclave(String baseUrl, String credentials, HttpClient httpClient, String enclavePubB64) {
        byte[] nonceBinary = new byte[24];
        try {
            SecureRandom.getInstanceStrong().nextBytes(nonceBinary);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate nonce: " + e.getMessage(), e);
        }
        String nonce = Base64.getEncoder().encodeToString(nonceBinary);

        System.out.println("Generated Nonce: " + nonce);

        byte[] encryptedNonce = encryptData(nonce.getBytes());
        String encryptedNonceB64 = Base64.getEncoder().encodeToString(encryptedNonce);

        try {
            Map<Object, Object> data = new HashMap<>();
            data.put("publicKey", enclavePubB64);
            data.put("encryptedNonce", encryptedNonceB64);
            String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();

            java.net.http.HttpRequest quoteRequest =
                    java.net.http.HttpRequest.newBuilder()
                            .uri(new java.net.URI(baseUrl + "/quote"))
                            .header("Authorization", "Basic " + credentials)
                            .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                            .POST(ofMultipartData(data, boundary))
                            .build();

            java.net.http.HttpResponse<String> quoteResponse =
                    httpClient.send(quoteRequest, java.net.http.HttpResponse.BodyHandlers.ofString());

            if (quoteResponse.statusCode() != 200) {
                throw new RuntimeException("Failed to get enclave quote: " + quoteResponse.body());
            }
            String encryptedQuoteB64 = quoteResponse.body();
            String decryptedQuoteB64 = new String(decryptData(Base64.getDecoder().decode(encryptedQuoteB64)), StandardCharsets.UTF_8);

            verifyQuote(decryptedQuoteB64, nonce);
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to verify enclave: " + e.getMessage(), e);
        }
    }

    private void startVerificationJob(String filename, String baseUrl, String credentials, HttpClient httpClient, String enclavePubB64) {
        Path encFilePath;
        try {
            encFilePath = Paths.get(encryptFile(filename));
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt payload: " + e.getMessage(), e);
        }

        HttpResponse<String> response;
        try {

            Map<Object, Object> data = new HashMap<>();
            data.put("file", encFilePath);
            data.put("publicKey", enclavePubB64);
            String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();

            // start verification
            response =
                    httpClient.send(
                            java.net.http.HttpRequest.newBuilder()
                                    .uri(new java.net.URI(baseUrl + "/process"))
                                    .header("Authorization", "Basic " + credentials)
                                    .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                                    .POST(ofMultipartData(data, boundary))
                                    .build(),
                            HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to start the verification: " + response.body());
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to send verification request: " + e.getMessage(), e);
        }
    }

    private String pollForResults(String filename, String baseUrl, String credentials, HttpClient httpClient, String enclavePubB64) {
        HttpResponse<byte[]> pollResp;
        boolean completed = false;
        Path outputFile = Paths.get("enc_response_" + new File(filename).getName());

        try {
            while (!completed) {
                Thread.sleep(10000); // wait 10 seconds between polls

                HttpRequest pollRequest =
                        HttpRequest.newBuilder()
                                .uri(
                                        new URI(
                                                baseUrl
                                                        + "/process?publicKey="
                                                        + URLEncoder.encode(enclavePubB64, StandardCharsets.UTF_8)))
                                .header("Authorization", "Basic " + credentials)
                                .GET()
                                .build();

                pollResp = httpClient.send(pollRequest, HttpResponse.BodyHandlers.ofByteArray());

                if (pollResp.statusCode() == 200) {
                    System.out.println("Result ready, downloading...");
                    Files.write(outputFile, pollResp.body());
                    completed = true;
                } else {
                    System.out.println(
                            "Result not ready yet (status "
                                    + pollResp.statusCode()
                                    + "): "
                                    + new String(pollResp.body(), StandardCharsets.UTF_8));
                }
            }
            return outputFile.toString();
        } catch (Exception e) {
            System.err.println("Failed to download results: " + e.getMessage());
            throw new RuntimeException("Error while polling for results: " + e.getMessage(), e);
        }
    }

    public void run(String host, int port, String username, String password, String filename) {
        HttpClient httpClient = HttpClient.newHttpClient();
        String credentials =
                Base64.getEncoder()
                        .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));

        final String baseUrl = "http://" + host + ":" + port + "/verifier";

        register(username, password, baseUrl, httpClient);

        PublicKey enclavePub = init(baseUrl, credentials, httpClient);
        String enclavePubB64 = Base64.getEncoder().encodeToString(enclavePub.getEncoded());

        shakeHands(baseUrl, credentials, httpClient, enclavePub, enclavePubB64);

        String skipAttestation = System.getenv("SKIP_ATTESTATION");
        if (skipAttestation == null || !skipAttestation.equals("1")) {
            attestEnclave(baseUrl, credentials, httpClient, enclavePubB64);
        }

        startVerificationJob(filename,  baseUrl, credentials, httpClient, enclavePubB64);

        System.out.println("Verification job started. Polling for results...");

        String outputFile = pollForResults(filename, baseUrl, credentials, httpClient, enclavePubB64);

        try {
            // Decrypt the response file
            String decryptedFilename = decryptFile(outputFile);
            System.out.println("Decrypted result from enclave: " + decryptedFilename);
        } catch (Exception e) {
            throw new RuntimeException("Error during run: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypt data with AES-GCM
     * @param encData The encrypted data
     * @return The decrypted data
     */
    private byte[] decryptData(byte[] encData) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonceBinary);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
            return cipher.doFinal(encData);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt data: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypt a file
     * @param filename The name of the file to decrypt
     * @return The name of the decrypted file
     */
    private String decryptFile(String filename) {
        try {
            byte[] fileData = Files.readAllBytes(Paths.get(filename));
            byte[] decData = decryptData(fileData);

            String decFilename = "dec_" + new File(filename).getName();
            Files.write(Paths.get(decFilename), decData);
            return decFilename;
        } catch (IOException e) {
            throw new RuntimeException("Failed to decrypt file: " + e.getMessage(), e);
        }
    }

    /**
     * Encrypt data with AES-GCM
     * @param data The data to encrypt
     * @return The encrypted data
     */
    private byte[] encryptData(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonceBinary);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt data: " + e.getMessage(), e);
        }
    }

    private String encryptFile(String filename) {
        try {
            byte[] fileData = Files.readAllBytes(Paths.get(filename));
            byte[] encData = encryptData(fileData);

            String encFilename = "enc_" + new File(filename).getName();
            Files.write(Paths.get(encFilename), encData);
            return encFilename;
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt file: " + e.getMessage(), e);
        }
    }

    public static void main(String[] args) {

        String host = "localhost";
        String port = "8080";
        String userName = "test";
        String password = "test";
        String filename = "../../data/test.zip";

        Console cnsl = System.console();

        if (cnsl == null) {
            System.out.println("No console available");

            System.out.println("Using default parameters: ");
            System.out.println("Host: " + host);
            System.out.println("Port: " + port);
            System.out.println("Username: " + userName);
            System.out.println("Filename: " + filename);
        } else {
            String hostInput = cnsl.readLine("Enter service host (default: localhost): ");
            if (hostInput != null && !hostInput.isEmpty()) {
                host = hostInput;
            }
            String portInput = cnsl.readLine("Enter service port (default: 8080): ");
            if (portInput != null && !portInput.isEmpty()) {
                port = portInput;
            }
            String userNameInput = cnsl.readLine("Enter username (default: test): ");
            if (userNameInput != null && !userNameInput.isEmpty()) {
                userName = userNameInput;
            }

            String passwordInput = new String(cnsl.readPassword("Enter password: "));
            if (!passwordInput.isEmpty()) {
                password = passwordInput;
            }

            String filenameInput = cnsl.readLine("Enter filename to process (default: test.zip): ");
            if (filenameInput != null && !filenameInput.isEmpty()) {
                filename = filenameInput;
            }
        }

        RemoteClient client = new RemoteClient();
        client.run(host, Integer.parseInt(port), userName, password, filename);
    }
}
