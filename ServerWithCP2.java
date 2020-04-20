import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class ServerWithCP2 {

	public static void main(String[] args) throws Exception {

		// get server cert
		X509Certificate serverCert = CertificateReader
				.get("keys_certificate/example-19fb0430-7c8f-11ea-ae9d-89114163ae84.crt");

		// read S private key
		PrivateKey serverPrivateKey;
		serverPrivateKey = PrivateKeyReader.get("keys_certificate/private_key.der");
		System.out.println(serverPrivateKey);
		System.out.println();

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

			int packetCount = 0;

			Key AESKey = new SecretKeySpec("hi".getBytes(), 0, 1, "AES");
			// stateless, keep looping to get packet type, read packet
			while (!connectionSocket.isClosed()) {
				int packetType = fromClient.readInt();
				// AP
				// do authentication
				String clientMessage;
				if (packetType == 69) {
					System.out.println("client requested for authentication");
					clientMessage = fromClient.readUTF();
					String encryptedClientMessage = Base64.getEncoder()
							.encodeToString(RSA.encrypt(clientMessage.getBytes(), serverPrivateKey));
					toClient.writeUTF(encryptedClientMessage);
					System.out.println();
				}
				if (packetType == 70) {
					toClient.writeUTF(Base64.getEncoder().encodeToString(serverCert.getEncoded()));
					// break;
				}
				if (packetType == 71) {
					System.out.println("client closed connection due to failed AP");
				}
				if (packetType == 72) {
					// read message from socket
					String symKey = fromClient.readUTF();
					byte[] decodedKey = RSA.decrypt(Base64.getDecoder().decode(symKey), serverPrivateKey);
					System.out.println("Received symmetric key");
					AESKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
					symKey = Base64.getEncoder().encodeToString(AESKey.getEncoded());
					System.out.println("symKey is: " + symKey);
					System.out.println();
				}

				// If the packet is for transferring the filename
				if (packetType == 0) { // 0 => file name

					// reset packet count for new file
					packetCount = 0;

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
					// receive 3 packets
					// numBytes = number of bytes before encryption, to be written
					// numBytesEncrypted = number of bytes after encryption, to be read from the buffer

					// receive all 3 packets
					int numBytes = fromClient.readInt();
					int numBytesEncrypted = fromClient.readInt();
					byte[] block = new byte[numBytesEncrypted];
					fromClient.readFully(block, 0, numBytesEncrypted);

					// count
					packetCount++;
					// System.out.println("packetCount:" + packetCount);

					// decrypt the data
					// byte[] blockDecrypted = RSA.decrypt(block, serverPrivateKey);
					// byte[] encodedKey = decoder.decodeBuffer(keyString);
					System.out.println(Base64.getEncoder().encodeToString(AESKey.getEncoded()));
					byte[] blockDecrypted = AES.decrypt(block, AESKey);

					// print the packet in string
					// System.out.println(Base64.getEncoder().encodeToString(blockDecrypted));
					System.out.println(new String(block));
					System.out.println(new String(blockDecrypted));
					System.out.println();

					if (numBytes > 0)
						bufferedFileOutputStream.write(blockDecrypted, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Received file");
						System.out.println("Total packets received: " + packetCount);
						System.out.println("");
						if (bufferedFileOutputStream != null)
							bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null)
							fileOutputStream.close();
					}
				}
				if (packetType == 4) { // 4 => End of transfer
					System.out.println("Closing connection...");
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}