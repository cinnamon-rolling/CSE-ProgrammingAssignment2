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
		System.out.println();
		System.out.println(serverPrivateKey);

		int port = 4321;
		if (args.length > 0)
			port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		// send symmetric key
		ServerSocket symKeySocket = null;
		Socket toConnect = null;
		DataOutputStream keyOut = null;
		DataInputStream keyIn = null;

		InputStream inStream = null;
		BufferedOutputStream bufferedSymKey = null;

		int portKey = 1234;
		
		try {
			symKeySocket = new ServerSocket(portKey);
			toConnect = symKeySocket.accept();
			System.out.println("Connection from 1234 accepted");
	
			// get input stream from connected socket
			inStream = toConnect.getInputStream();
			// read data from instread socket
			keyIn = new DataInputStream(inStream);
	
			// read message from socket
			String symKey = keyIn.readUTF();
			System.out.println("symKey is: " + symKey);
			
			// close
			symKeySocket.close();
			toConnect.close();
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			int packetCount = 0;

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
					toClient.writeUTF(Base64.getEncoder().encodeToString(serverCert.getEncoded()));
					// break;
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
					System.out.println("packetCount:" + packetCount);

					// decrypt the data
					// byte[] blockDecrypted = RSA.decrypt(block, serverPrivateKey);
					// byte[] encodedKey = decoder.decodeBuffer(keyString);
					byte[] decodedKey = Base64.getDecoder().decode(symKey);
					Key symkey = new SecretKeySpec(decodedKey, 0 ,decodedKey.length, "AES");  
					// getDecoder().decode(symKey), 0, symKey.length, "AES");
					byte[] blockDecrypted = AES.decrypt(block, symkey);

					// print the packet in string
					System.out.println(Base64.getEncoder().encodeToString(blockDecrypted));

					if (numBytes > 0)
						bufferedFileOutputStream.write(blockDecrypted, 0, numBytes);

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
