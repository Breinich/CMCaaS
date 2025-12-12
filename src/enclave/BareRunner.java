import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class BareRunner {

    private static final String INPUT_DIR = "/tmp/input";
    private static final String EXTRACTION_DIR = "/tmp/extracted";
    private static final String OUTPUT_DIR = "/tmp/output";
    private boolean stop = false;


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
                     new ZipInputStream(new FileInputStream(Paths.get(INPUT_DIR, filename).toFile()))) {
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
                if (file.getName().endsWith(".i") || file.getName().endsWith(".c")) {
                    if (inputFilePath != null) {
                        throw new IllegalArgumentException("Multiple input files found");
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
            throw new IllegalArgumentException("Expected exactly one .i or .c input file, found none");
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

    private String verifyModel(String filename) {
        if (!java.nio.file.Files.exists(java.nio.file.Paths.get(INPUT_DIR, filename))) {
            System.err.println("File not found: " + filename);
            throw new IllegalArgumentException("File not found");
        }
        if (!filename.endsWith(".zip")) throw new IllegalArgumentException("File must be a .zip file");
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\"))
            throw new IllegalArgumentException("Invalid filename");

        return processFile(filename).getFileName().toString();
    }

    public BareRunner(int port) throws Exception {

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
            case "process":
                System.out.println("PROCESS_COMMAND_RECEIVED");

                String filename = in.readUTF();
                System.out.println("FILENAME=" + filename);
                if (filename.trim().isEmpty()) {
                    throw new IllegalArgumentException("No filename received");
                }
                String result_name = verifyModel(filename);

                // Step 4: send back the output filename
                out.writeUTF(result_name);
                out.flush();
                System.out.println("OUTPUT_FILENAME=" + result_name);
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
        new BareRunner(port);
    }
}
