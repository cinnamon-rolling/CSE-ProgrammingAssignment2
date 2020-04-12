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

class PublicKeyReader {

	public static PublicKey get(String filename) throws Exception {

		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
}

class CertificateReader {

	public static X509Certificate get(String filename) throws Exception {
		InputStream inputStream = new FileInputStream(filename);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		return (X509Certificate) cf.generateCertificate(inputStream);
	}
}

public class ClientWithAP {

	public static void main(String[] args) {
		try {
			// get server cert
			X509Certificate serverCert = CertificateReader
					.get("keys_certificate_2/example-e0067250-7c9d-11ea-ae9d-89114163ae84.crt");
			serverCert.checkValidity();

			// get server public key
			PublicKey serverPublicKey = serverCert.getPublicKey();
			System.out.println(serverPublicKey);

			// get CA cert
			X509Certificate CAcert = CertificateReader
					.get("keys_certificate/cacse.crt");

			// get CA public key
			PublicKey CAPublicKey = CAcert.getPublicKey();
			System.out.println(CAPublicKey);

			System.out.println("serverPublicKey: " + serverPublicKey);
			System.out.println("CAPublicKey: " + CAPublicKey);
			serverCert.verify(CAPublicKey);
			System.out.println("Server's certificate is verified");
		} catch (Exception e) {
			System.out.println("[ERROR!] " + e);
		}

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

			System.out.println("Sending file...");

			// Send the filename
			toServer.writeInt(0);
			toServer.writeInt(filename.getBytes().length);
			toServer.write(filename.getBytes());
			//toServer.flush();

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

			byte[] fromFileBuffer = new byte[117];

			// Send the file
			for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 117;

				toServer.writeInt(1);
				toServer.writeInt(numBytes);
				toServer.write(fromFileBuffer);
				toServer.flush();
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
