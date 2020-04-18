import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

public class ServerWithAP {

	public static void main(String[] args) {

		// read S private key
		PrivateKey serverPrivateKey;
		try {
			serverPrivateKey = PrivateKeyReader.get("keys_certificate/private_key.der");
			System.out.println();
			System.out.println(serverPrivateKey);
		} catch (Exception e) {
			e.printStackTrace();
		}

		int port = 4321;
		if (args.length > 0)
			port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			// stateless, keep looping to get packet type, read packet
			while (!connectionSocket.isClosed()) {
				int packetType = fromClient.readInt();
				// AP
				// do authentication
				if (packetType == 69) {
					System.out.println("client requested for authentication");
					toClient.writeUTF("hi, this is secstore");
				}
				if (packetType == 70) {
					toClient.writeUTF("valid_cert");
				}
				if (packetType == 71) {
					System.out.println("client closed connection due to failed AP");
				}

				// If the packet is for transferring the filename
				if (packetType == 0) { // 0 => file name

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte[] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

					// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) { // 1 => file chunk

					int numBytes = fromClient.readInt();
					byte[] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null)
							bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null)
							fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}

			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
