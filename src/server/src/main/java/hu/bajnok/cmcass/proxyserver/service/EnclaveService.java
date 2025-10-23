package hu.bajnok.cmcass.proxyserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class EnclaveService {

    private static final String ENCLAVE_CMD = "/app/scripts/run_verifier.sh";
    private static final String ENCLAVE_TOOL = "verifier";
    private static final String ENCLAVE_PREFIX = "occlum_verifier_";
    private static final String INPUT_FILE = "input.zip";
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
     * @param username Authenticated user's username
     * @return Enclave public key in Base64 encoding
     * @throws IOException if fails to start the process or communicate with it
     */
    public String launch_enclave(String username) throws IOException {
        launchLock.lock();
        try {
            String enclavePublicKey_b64 = "";
            final int new_id = dbService.getNewProcessPort();
            int port = BASE_PORT + new_id;

            ProcessBuilder pb = new ProcessBuilder(ENCLAVE_CMD, ENCLAVE_TOOL, String.valueOf(port));

            final Process process = pb.start();

            executor.submit(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        logger.info("[Enclave-{} STDOUT] {}", new_id, line);
                    }
                } catch (IOException e) {
                    logger.error("Error reading enclave stdout", e);
                }
            });

            executor.submit(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        logger.error("[Enclave-{} STDERR] {}", new_id, line);
                    }
                } catch (IOException e) {
                    logger.error("Error reading enclave stderr", e);
                }
            });

            int attempts = 0;
            final int maxAttempts = 240; // max 120 seconds if sleep=500ms
            boolean started = false;

            while(attempts < maxAttempts){
                try(Socket s = new Socket(HOST, port)) {
                    DataInputStream in = new DataInputStream(s.getInputStream());
                    DataOutputStream out = new DataOutputStream(s.getOutputStream());

                    out.writeUTF("init");
                    out.flush();

                    enclavePublicKey_b64 = in.readUTF();
                    logger.info("Enclave launched on port " + port + " with public key: " + enclavePublicKey_b64);
                    started = true;
                    break;
                }
                catch (IOException e){
                    try {
                        Thread.sleep(500);
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

            // leave the process running and save its port number for later use

            dbService.addProcess(username, new_id, enclavePublicKey_b64);
            executor.submit(() -> {
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
        }
        finally {
            // Always release the lock even if thrown earlier
            launchLock.unlock();
        }
    }

    /**
     * Process the uploaded file by sending it to the enclave process
     * @param username username of the authenticated user
     * @param file uploaded file
     * @param clientDataB64 Base64 encoded client data
     * @param processKey public key of the enclave process
     * @return Path to the encrypted output file
     * @throws IOException if communication with the enclave fails
     */
    public Path process_task(String username, MultipartFile file, String clientDataB64, String processKey) throws IOException {
        // 1. Get the process related to the user
        int processId;
        try {
            logger.info("Retrieving process ID for user: {} with process key: {}", username, processKey);
            processId = dbService.getProcessPort(username, processKey);
        }
        catch (Exception e) {
            throw new IllegalStateException("Enclave process is not running: " + e.getMessage());
        }

        int port = BASE_PORT + processId;

        // save the uploaded file to the enclave's directory
        Path path = Paths.get(ENCLAVE_PREFIX + port, INPUT_FILE);
        file.transferTo(path);

        // connect to the enclave process
        try (Socket s = new Socket(HOST, port)) {
            String encryptedOutputFileName = getEnclaveProcessResult(clientDataB64, s);

            logger.info("Received encrypted output filename: " + encryptedOutputFileName);

            return Paths.get(ENCLAVE_PREFIX + port, encryptedOutputFileName);
        }
        catch (IOException e) {
            // if communication fails, assume the enclave process is down, clean up the database
            dbService.stopProcess(username, processKey);
            throw new IllegalStateException("Enclave process is not running");
        }
    }

    /**
     * Send process command to the enclave and get the result filename
     * @param clientDataB64 client data in Base64 encoding
     * @param s connected socket to the enclave process
     * @return encrypted output filename
     * @throws IOException if communication fails
     */
    private static String getEnclaveProcessResult(String clientDataB64, Socket s) throws IOException {
        DataOutputStream out = new DataOutputStream(s.getOutputStream());
        out.writeUTF("process");
        out.flush();

        // send client data
        out.writeUTF(clientDataB64);
        out.flush();
        // send filename
        out.writeUTF(INPUT_FILE);
        out.flush();
        // read encrypted output filename
        DataInputStream in = new DataInputStream(s.getInputStream());
        return in.readUTF();
    }

    /**
     * Stop the enclave process associated with the user
     * @param username username of the authenticated user
     * @param processKey public key of the enclave process
     */
    public void stop_enclave(String username, String processKey) {
        int processId;
        try {
            processId = dbService.getProcessPort(username, processKey);
        }
        catch (IllegalArgumentException e) {
            throw new IllegalStateException("Enclave process is not running");
        }
        int port = BASE_PORT + processId;
        // connect to the enclave process and close the socket to signal termination
        try (Socket s = new Socket(HOST, port)) {
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            out.writeUTF("stop");
            out.flush();
        }
        catch (IOException ignored) {}
        finally {
            dbService.stopProcess(username, processKey);
        }
    }
}

