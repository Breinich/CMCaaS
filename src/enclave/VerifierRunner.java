import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.crypto.*;
import javax.crypto.spec.*;

/** enclave.RobustEnclaveApp */
public class VerifierRunner {
  private static final String SHARED_DIR = "/host";
  private static final String EXTRACTION_DIR = "/tmp/extracted";
  private static final String DECRYPTED_DIR = "/tmp/decrypted";
  private static final String OUTPUT_DIR = "/tmp/output";

  private PrivateKey privateKey;
  private PublicKey publicKey;
  private byte[] nonce;
  private SecretKey aesKey;
  private boolean stop = false;

  /** Generate EC key pair (secp256r1) */
  private void generateKeyPair() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair kp = keyGen.generateKeyPair();
    privateKey = kp.getPrivate();
    publicKey = kp.getPublic();
  }

  /**
   * Export public key as Base64 (X.509 encoded)
   *
   * @return Base64 string
   */
  private String exportPublicKey() {
    return Base64.getEncoder().encodeToString(publicKey.getEncoded());
  }

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
   *
   * @param encryptedMessageBase64 Base64-encoded encrypted payload
   */
  private void decryptPayload(String encryptedMessageBase64) throws Exception {
    byte[] payload = Base64.getDecoder().decode(encryptedMessageBase64);
    ByteBuffer buf = ByteBuffer.wrap(payload);

    // Read clientPubLen + clientPub
    int clientPubLen = buf.getInt();
    if (clientPubLen <= 0 || clientPubLen > buf.remaining())
      throw new IllegalArgumentException("bad clientPubLen");
    byte[] clientPubBytes = new byte[clientPubLen];
    buf.get(clientPubBytes);

    // nonce
    int nonceLen = buf.getInt();
    if (nonceLen <= 0 || nonceLen > buf.remaining())
      throw new IllegalArgumentException("bad nonceLen");
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
   *
   * @param filename file name
   */
  private void decryptFile(String filename) throws Exception {
    // Ensure decrypted directory exists
    java.nio.file.Files.createDirectories(java.nio.file.Paths.get(DECRYPTED_DIR));

    // Ensure encryption context is present
    if (aesKey == null || nonce == null) {
      throw new IllegalStateException(
          "Missing encryption context: PUBLICKEY header must be sent before VERIFY");
    }

    // Decrypt AES-GCM
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
    cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

    // Read encrypted file
    Path inPath = Paths.get(SHARED_DIR, filename);
    Path outPath = Paths.get(DECRYPTED_DIR, filename);

    if (!java.nio.file.Files.exists(inPath)) {
      throw new FileNotFoundException("Encrypted input file not found: " + inPath);
    }

    byte[] encFile = java.nio.file.Files.readAllBytes(inPath);
    // Decrypt
    byte[] decFile = cipher.doFinal(encFile);

    // Ensure parent directories for the output file exist
    if (outPath.getParent() != null) {
      java.nio.file.Files.createDirectories(outPath.getParent());
    }

    // Write the decrypted file
    java.nio.file.Files.write(outPath, decFile);

    System.out.println("Decrypted file: " + filename);
  }

  private static String sanitizeFilename(String filename) {
    return filename.replaceAll("[^a-zA-Z0-9._-]", "_");
  }

  /**
   * Unzip the file and run the model checking
   *
   * @param filename file name
   * @return output file path (txt)
   */
  private Path processFile(String filename) {
    System.out.println("Processing file: " + filename);

    // Ensure extraction and output directories exist
    try {
      java.nio.file.Files.createDirectories(java.nio.file.Paths.get(EXTRACTION_DIR));
      java.nio.file.Files.createDirectories(java.nio.file.Paths.get(OUTPUT_DIR));
    } catch (IOException e) {
      throw new RuntimeException("Unable to create working directories: " + e.getMessage(), e);
    }

    // extract the zip file
    try (ZipInputStream zis =
        new ZipInputStream(new FileInputStream(Paths.get(DECRYPTED_DIR, filename).toFile()))) {
      ZipEntry entry;
      while ((entry = zis.getNextEntry()) != null) {
        File outFile = new File(EXTRACTION_DIR, sanitizeFilename(entry.getName()));
        if (entry.isDirectory()) {
          outFile.mkdirs();
        } else {
          // Ensure parent exists
          File parent = outFile.getParentFile();
          if (parent != null && !parent.exists()) parent.mkdirs();
          try (FileOutputStream fos = new FileOutputStream(outFile)) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = zis.read(buffer)) > 0) {
              fos.write(buffer, 0, len);
            }
          }
        }
        zis.closeEntry();
      }
    } catch (IOException e) {
      throw new RuntimeException("Error extracting zip file: " + e.getMessage(), e);
    }

    System.out.println("Starting verification...");

    // Prepare command arguments for the external verifier
    String inputFilePath = null;
    String propertyFilePath = null;

    File extractionDir = new File(EXTRACTION_DIR);
    File[] files = extractionDir.listFiles();
    if (files == null) files = new File[0];

    for (File file : files) {
      if (file.isFile()) {
        if (file.getName().endsWith(".i")) {
          if (inputFilePath != null) {
            throw new IllegalArgumentException("Multiple .i input files found");
          }
          inputFilePath = file.getAbsolutePath();
        } else if (file.getName().endsWith(".prp")) {
          if (propertyFilePath != null) {
            throw new IllegalArgumentException("Multiple .prp property files found");
          }
          propertyFilePath = file.getAbsolutePath();
        }
      }
    }
    if (inputFilePath == null) {
      throw new IllegalArgumentException("Expected exactly one .i input file, found none");
    }

    File logFile = new File(OUTPUT_DIR, "theta-log.txt");

    try {
      logFile.getParentFile().mkdirs();
      logFile.createNewFile();
    } catch (IOException e) {
      throw new RuntimeException("Unable to create log file: " + e.getMessage(), e);
    }

    try {
      // Build full command: executable + input + properties
      List<String> command = new ArrayList<>();
      command.add("/usr/lib/jvm/java-21-openjdk-amd64/bin/java");
      command.add("-Xss1m");
      command.add(
          "-Xmx"
              + (System.getenv("THETA_XMX") != null && !System.getenv("THETA_XMX").isEmpty()
                  ? System.getenv("THETA_XMX")
                  : "512m"));
      command.add("-Djdk.lang.Process.launchMechanism=posix_spawn");
      command.add("-XX:-UseCompressedOops");
      command.add("-XX:MaxMetaspaceSize=64m");
      command.add("-Dos.name=Linux");
      command.add("-jar");
      command.add("/theta/theta.jar");
      command.add("--input");
      command.add(inputFilePath);
      command.add("--property");
      command.add(propertyFilePath);
      command.add("--smt-home");
      command.add("/theta/solvers");

      ProcessBuilder pb = new ProcessBuilder(command);
      pb.directory(new File("/theta"));
      pb.environment().put("LD_LIBRARY_PATH", System.getenv("LD_LIBRARY_PATH") + ":/theta/lib");

      pb.redirectErrorStream(true);
      pb.redirectOutput(logFile);

      Process process = pb.start();
      int exitCode = process.waitFor();

      // measure CPU time
      Optional<Duration> cpuDuration = process.info().totalCpuDuration();
        cpuDuration.ifPresent(
            duration ->
                System.out.println("CPU time used by verification process: " + duration.toMillis() + " ms"));

      if (exitCode != 0) {
        System.err.println("Verification process failed with exit code: " + exitCode);
        throw new RuntimeException("Verification process failed with exit code: " + exitCode);
      } else {
        System.out.println("Verification completed successfully.");
      }
    } catch (Exception e) {
      try {
        List<String> logLines = java.nio.file.Files.readAllLines(logFile.toPath());
        System.err.println("Verification log:");
        for (String line : logLines) {
          System.err.println(line);
        }
      } catch (IOException ioException) {
        System.err.println("Unable to read log file: " + ioException.getMessage());
      }
      throw new RuntimeException("Error during verification process: " + e.getMessage(), e);
    }

    Path result_zip = Paths.get(OUTPUT_DIR, "results.zip");
    try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(result_zip.toFile()))) {
      ZipEntry logEntry = new ZipEntry("theta-log.txt");
      zos.putNextEntry(logEntry);
      byte[] logBytes = java.nio.file.Files.readAllBytes(logFile.toPath());
      zos.write(logBytes, 0, logBytes.length);
      zos.closeEntry();
    } catch (Exception e) {
      throw new RuntimeException("Error creating zipped log file: " + e.getMessage(), e);
    }

    return result_zip;
  }

  /**
   * Encrypt the output file
   *
   * @param resultPath file name
   * @return encrypted file name
   */
  private String encryptResults(Path resultPath) throws Exception {

    byte[] fileBytes = java.nio.file.Files.readAllBytes(resultPath);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

    byte[] encFile = cipher.doFinal(fileBytes);
    String encryptedFilename = "enc_" + resultPath.getFileName().toString();

    // Ensure shared dir exists
    java.nio.file.Files.createDirectories(java.nio.file.Paths.get(SHARED_DIR));

    java.nio.file.Files.write(java.nio.file.Paths.get(SHARED_DIR, encryptedFilename), encFile);

    System.out.println("Encrypted output file: " + encryptedFilename);
    return encryptedFilename;
  }

  private String verifyModel(String filename) throws Exception {
    if (!java.nio.file.Files.exists(java.nio.file.Paths.get(SHARED_DIR, filename))) {
      System.err.println("File not found: " + filename);
      throw new IllegalArgumentException("File not found");
    }
    if (!filename.endsWith(".zip")) throw new IllegalArgumentException("File must be a .zip file");
    if (filename.contains("..") || filename.contains("/") || filename.contains("\\"))
      throw new IllegalArgumentException("Invalid filename");

    decryptFile(filename);

    Path resultFilePath = processFile(filename);

    return encryptResults(resultFilePath);
  }

  public VerifierRunner(int port) throws Exception {
    generateKeyPair();

    try (ServerSocket server = new ServerSocket(port, 10, InetAddress.getByName("127.0.0.1"))) {
      System.out.println("Verifier enclave listening on 127.0.0.1:" + port);

      while (!stop) {
        Socket client = server.accept();
        Thread t =
            new Thread(
                () -> {
                  try {
                    handle(client);
                  } catch (Throwable t1) {
                    System.err.println("Error handling client: " + t1.getMessage());
                  } finally {
                    try {
                      client.close();
                    } catch (IOException ignored) {
                    }
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
