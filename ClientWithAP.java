import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class ClientWithAP {

	public static void main(String[] args) throws Exception {

		// get CA cert
		X509Certificate CAcert = CertificateReader.get("keys_certificate/cacse.crt");

		// get CA public key
		PublicKey CAPublicKey = CAcert.getPublicKey();
		System.out.println("CAPublicKey: " + CAPublicKey);

		String filename = "100.txt";
		if (args.length > 0)
			filename = args[0];

		String serverAddress = "localhost";
		if (args.length > 1)
			filename = args[1];

		int port = 4321;
		if (args.length > 2)
			port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

		DataOutputStream toServer = null;
		DataInputStream fromServer = null;

		FileInputStream fileInputStream = null;
		BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			// do authentication
			toServer.writeInt(69); // 69 => ask to prove identity
			String encryptedM = fromServer.readUTF();
			toServer.writeInt(70); // 70 => ask for cert signed by CA

			// receive cert from server
			System.out.println("receiving server's certificate in string");
			String serverCertString = fromServer.readUTF();
			X509Certificate serverCert = CertificateReader.get_from_string(serverCertString);

			// get server public key
			PublicKey serverPublicKey = serverCert.getPublicKey();
			System.out.println("serverPublicKey: " + serverPublicKey);

			// verify server's certificate
			try {
				serverCert.checkValidity();
				serverCert.verify(CAPublicKey);
			} catch (Exception e) {
				e.printStackTrace();
				toServer.writeInt(71); // 71 => invalid cert, close connection
				System.out.println("Closing connection...");
				clientSocket.close();
			}
			System.out.println("Server's certificate is verified");

			// begin handshake for file upload
			System.out.println("Sending file...");
			// Send the filename
			toServer.writeInt(0); // 0 => file name
			toServer.writeInt(filename.getBytes().length);
			toServer.write(filename.getBytes());
			//toServer.flush();

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

			byte[] fromFileBuffer = new byte[117];

			int packetCount = 0;

			// Send the file
			for (boolean fileEnded = false; !fileEnded;) {
				// send 3 packets
				// numBytes = number of bytes before encryption, to be written
				// numBytesEncrypted = number of bytes after encryption, to be read from the buffer

				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 117;

				toServer.writeInt(1); // 1 => file chunk
				toServer.writeInt(numBytes);
				System.out.println(numBytes);

				System.out.println("original bytes: " + fromFileBuffer);
				System.out.println("before encryption length: " + fromFileBuffer.length);

				// encrypt the data
				byte[] fromFileBufferEncrypted = RSA.encrypt(fromFileBuffer, serverPublicKey);

				int numBytesEncryted = fromFileBufferEncrypted.length;
				toServer.writeInt(numBytesEncryted);
				System.out.println(numBytesEncryted);

				// send the data
				toServer.write(fromFileBufferEncrypted);
				toServer.flush();

				// count and print the packet in string
				packetCount++;
				System.out.println("packetCount:" + packetCount);
				System.out.println(Base64.getEncoder().encodeToString(fromFileBuffer));

			}

			bufferedFileInputStream.close();
			fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {
			e.printStackTrace();
		}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
	}
}
