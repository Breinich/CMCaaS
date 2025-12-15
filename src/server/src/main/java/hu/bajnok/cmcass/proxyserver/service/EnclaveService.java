package hu.bajnok.cmcass.proxyserver.service;

import hu.bajnok.cmcass.proxyserver.model.ProcessStatus;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EnclaveService {

  private static final String ENCLAVE_CMD = "/app/scripts/run_verifier.sh";
  private static final String ENCLAVE_TOOL = "verifier";
  private static final String ENCLAVE_PREFIX = "occlum_verifier_";
  private static final String INPUT_FILE = "input.zip";
  private static final String OUTPUT_FILE = "output.zip";
  private static final int BASE_PORT = 5000;

  private static final String HOST = "localhost";

  private final DataBaseService dbService;
  private final ExecutorService executor = Executors.newCachedThreadPool();
  private static final Logger logger = LoggerFactory.getLogger(EnclaveService.class);
  private final ReentrantLock launchLock = new ReentrantLock();

  public EnclaveService(DataBaseService dbService) {
    this.dbService = dbService;
  }

  /**
   * Launch enclave process attached to the authenticated user's ID
   *
   * @param username Authenticated user's username
   * @return Enclave public key in Base64 encoding
   * @throws IOException if fails to start the process or communicate with it
   */
  public String launchEnclave(String username) throws IOException {
    launchLock.lock();
    try {
      String enclavePublicKey_b64 = "";
      final int new_id = dbService.getNewProcessPort();
      int port = BASE_PORT + new_id;

      ProcessBuilder pb = new ProcessBuilder(ENCLAVE_CMD, ENCLAVE_TOOL, String.valueOf(port));

      final Process process = pb.start();

      executor.submit(
          () -> {
            try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(process.getInputStream()))) {
              String line;
              while ((line = reader.readLine()) != null) {
                logger.info("[Enclave-{} STDOUT] {}", new_id, line);
              }
            } catch (IOException e) {
              logger.error("Error reading enclave stdout", e);
            }
          });

      executor.submit(
          () -> {
            try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
              String line;
              while ((line = reader.readLine()) != null) {
                logger.error("[Enclave-{} STDERR] {}", new_id, line);
              }
            } catch (IOException e) {
              logger.error("Error reading enclave stderr", e);
            }
          });

      int attempts = 0;
      final int maxAttempts = 300; // max 300 seconds
      boolean started = false;

      while (attempts < maxAttempts) {
        try (Socket s = new Socket(HOST, port)) {
          DataInputStream in = new DataInputStream(s.getInputStream());
          DataOutputStream out = new DataOutputStream(s.getOutputStream());

          out.writeUTF("init");
          out.flush();

          enclavePublicKey_b64 = in.readUTF();
          logger.info(
              "Enclave launched on port {} with public key: {}", port, enclavePublicKey_b64);
          started = true;
          break;
        } catch (IOException e) {
          try {
            Thread.sleep(1000);
            attempts++;
          } catch (InterruptedException ie) {
            ie.printStackTrace();
          }
        }
      }

      if (!started) {
        process.destroy();
        throw new IOException("Failed to start enclave process within the expected time.");
      }

      dbService.addProcess(username, new_id, enclavePublicKey_b64, process.pid());
      logger.info(
          "Enclave process registered in database for user {} with ID: {}", username, new_id);

      executor.submit(
          () -> {
            try {
              int exitCode = process.waitFor();
              if (exitCode != 0) {
                logger.error("Enclave process exited with code {}", exitCode);
              } else {
                logger.info("Enclave process exited successfully");
              }
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
              logger.error("Waiting for enclave process interrupted", e);
            }
          });

      return enclavePublicKey_b64;
    } finally {
      launchLock.unlock();
    }
  }

  /**
   * Process the uploaded file by sending it to the enclave process
   *
   * @param username username of the authenticated user
   * @param tempFileName temporary file path of the uploaded file
   * @param processKey public key of the enclave process
   * @throws IOException if communication with the enclave fails
   */
  @Async("asyncExecutor")
  public void createVerificationJob(String username, Path tempFileName, String processKey)
      throws IOException {
    if (dbService.isVerificationInProgress(username, processKey)) {
      throw new IllegalArgumentException("A verification is already in progress for this enclave.");
    }

    int processPort;
    try {
      processPort = dbService.getProcessPort(username, processKey);
    } catch (Exception e) {
      throw new IllegalStateException("Enclave process is not running: " + e.getMessage());
    }

    int port = BASE_PORT + processPort;

    Path path = Paths.get(ENCLAVE_PREFIX + port, INPUT_FILE);
    Files.move(tempFileName, path, StandardCopyOption.REPLACE_EXISTING);

    try (Socket s = new Socket(HOST, port)) {
      logger.info("Connected to enclave process on port {}", port);
      dbService.updateProcessVerificationStatus(username, processKey, ProcessStatus.RUNNING);
      boolean success = startVerification(s);
      if (success) {
        dbService.updateProcessVerificationStatus(username, processKey, ProcessStatus.COMPLETED);
        logger.info(
            "Verification completed successfully for user {} enclave {}", username, processKey);
      } else {
        dbService.updateProcessVerificationStatus(username, processKey, ProcessStatus.ERROR);
        logger.error("Verification failed for user {} enclave {}", username, processKey);
      }
    } catch (IOException e) {
      // if communication fails, assume the enclave process is down, clean up the database
      dbService.stopProcess(username, processKey);
      throw new IllegalStateException(
          "Enclave process is not running or failed to start the verification.");
    }
  }

  /**
   * Send process command to the enclave and get the result filename
   *
   * @param s connected socket to the enclave process
   * @return true if verification finished successfully
   * @throws IOException if communication fails
   */
  private static boolean startVerification(Socket s) throws IOException {
    DataOutputStream out = new DataOutputStream(s.getOutputStream());
    out.writeUTF("process");
    out.flush();

    out.writeUTF(INPUT_FILE);
    out.flush();

    DataInputStream in = new DataInputStream(s.getInputStream());
    String resultFile = in.readUTF();

    if (!resultFile.isEmpty()) {
      Path source = Paths.get(ENCLAVE_PREFIX + s.getPort(), resultFile);
      Path target = Paths.get(ENCLAVE_PREFIX + s.getPort(), OUTPUT_FILE);
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
      logger.info("Received encrypted output filename: {}", resultFile);
      return true;
    }
    return false;
  }

  /**
   * Stop the enclave process associated with the user
   *
   * @param username username of the authenticated user
   * @param processKey public key of the enclave process
   */
  public void stop_enclave(String username, String processKey) {
    int processId;
    long pid;
    try {
      pid = dbService.getProcessPid(username, processKey);
      processId = dbService.getProcessPort(username, processKey);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException("Enclave process is not running");
    }
    int port = BASE_PORT + processId;
    try (Socket s = new Socket(HOST, port)) {
      DataOutputStream out = new DataOutputStream(s.getOutputStream());
      out.writeUTF("stop");
      out.flush();
    } catch (IOException ignored) {
    } finally {
      try {
        ProcessHandle.of(pid).ifPresent(ProcessHandle::destroy);
        dbService.stopProcess(username, processKey);
        logger.info("Enclave process with PID {} terminated.", pid);

      } catch (Exception e) {
        logger.error("Failed to terminate enclave process with PID {}: {}", pid, e.getMessage());
      }
    }
  }

  public byte[] getEncryptedResults(String username, String processKey) {
    if (dbService.verificationMissing(username, processKey)) {
      throw new IllegalArgumentException(
          "There isn't any verification in progress for this enclave.");
    }

    ProcessStatus status = dbService.getProcessVerificationStatus(username, processKey);

    if (status == ProcessStatus.RUNNING || status == ProcessStatus.CREATED) {
      logger.info("Verification is still in progress for user {} enclave {}", username, processKey);
      throw new IllegalStateException("Verification is still in progress.");
    } else if (status == ProcessStatus.ERROR) {
      return "Verification ended with an error.".getBytes(StandardCharsets.UTF_8);
    }

    logger.info("Verification ended successfully for user {} enclave {}", username, processKey);

    int processPort = dbService.getProcessPort(username, processKey);
    Path outputPath = Paths.get(ENCLAVE_PREFIX + (BASE_PORT + processPort), OUTPUT_FILE);

    try {
      return Files.readAllBytes(outputPath);
    } catch (IOException e) {
      logger.error("Failed to read output file for user {} enclave {}", username, processKey, e);
      throw new RuntimeException(e);
    }
  }

  /**
   * Perform handshake with the enclave process
   *
   * @param username the username of the user
   * @param clientDataB64 Base64-encoded client data
   * @param processKey the process key
   */
  public void shakeHands(String username, String clientDataB64, String processKey) {
    if (dbService.verificationMissing(username, processKey))
      throw new IllegalArgumentException(
          "There isn't any verification in progress for this enclave.");

    int processPort = dbService.getProcessPort(username, processKey);
    int port = BASE_PORT + processPort;

    try (Socket s = new Socket(HOST, port)) {
      DataOutputStream out = new DataOutputStream(s.getOutputStream());
      DataInputStream in = new DataInputStream(s.getInputStream());
      out.writeUTF("handshake");
      out.flush();

      out.writeUTF(clientDataB64);
      out.flush();

      String response = in.readUTF();

      if (!response.equals("OK")) {
        throw new IllegalStateException("Handshake failed with the enclave process.");
      }
    } catch (IOException e) {
      throw new IllegalStateException("Enclave process is not running or failed to communicate.");
    }
  }

  /**
   * Get the enclave quote
   *
   * @param username the username of the user
   * @param processKey the process key
   * @param encryptedNonceB64 the Base64-encoded and encrypted nonce
   * @return the enclave quote
   */
  public String getEnclaveQuote(String username, String processKey, String encryptedNonceB64) {
    if (dbService.verificationMissing(username, processKey))
      throw new IllegalArgumentException(
          "There isn't any verification in progress for this enclave.");

    int processPort = dbService.getProcessPort(username, processKey);
    int port = BASE_PORT + processPort;

    try (Socket s = new Socket(HOST, port)) {
      DataOutputStream out = new DataOutputStream(s.getOutputStream());
      DataInputStream in = new DataInputStream(s.getInputStream());
      out.writeUTF("quote");
      out.flush();

      out.writeUTF(encryptedNonceB64);
      out.flush();

      return in.readUTF();
    } catch (IOException e) {
      throw new IllegalStateException("Enclave process is not running or failed to communicate.");
    }
  }
}
