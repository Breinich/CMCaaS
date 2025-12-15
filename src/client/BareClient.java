import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;

/**
 * A simple client to communicate with the BareRunner to measure verification time outside of
 * enclave in a similar environment.
 */
public class BareClient {
  public static void main(String[] args) {
    String host = "127.0.0.1";
    if (args.length < 2) {
      System.out.println("Usage: java BareClient <port> <filename>");
      System.exit(1);
    }
    int port = Integer.parseInt(args[0]);
    String filename = args[1];

    try (Socket s = new Socket(host, port);
        DataOutputStream out = new DataOutputStream(s.getOutputStream());
        DataInputStream in = new DataInputStream(s.getInputStream())) {

      out.writeUTF("process");

      out.writeUTF(filename);
      out.flush();

      String resultFile = in.readUTF();
      System.out.println("Result received: " + resultFile);

    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}
