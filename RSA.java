import java.util.Base64;
import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.security.*;
import java.security.PublicKey;
import java.io.*;
import java.security.cert.X509Certificate;

// readfile and output file content in String
class ReadFile{
        public static String readFile(String filename) throws Exception{
                String fileName = filename;
                String data = "";
                String line;
                BufferedReader bufferedReader = new BufferedReader( new FileReader(fileName));
                while((line= bufferedReader.readLine())!=null){
                        data = data +"\n" + line;
                }
                return data;
                }
}

// RSA encryption
class RSAEncrypt{
        public static String encrypt(String filename) throws Exception{
                // read the text file and save to String data
                String fileName = "./testFile.txt";
                String data = ReadFile.readFile(fileName);
                
                // print out content of files
                System.out.println("Original content: "+ data);
                System.out.println(("Length of original content: " + data.length()));
        
                // compute digest using MD5 hash function
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(data.getBytes());
                byte[] digest = md.digest();

                // print out digest
                System.out.println("Message digest:" + digest);
                System.out.println("Length of digest: " + digest.length);
                

                // get server cert
                X509Certificate serverCert = CertificateReader
                        .get("keys_certificate/example-19fb0430-7c8f-11ea-ae9d-89114163ae84.crt");

                // check cert validity
                serverCert.checkValidity();

                // get server public key
                PublicKey serverPublicKey = serverCert.getPublicKey();
                System.out.println(serverPublicKey);
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
                byte[] encryptedBytes = rsaCipher.doFinal(digest);
                System.out.println("encryptedBytes: " + encryptedBytes + "\nLength of encryptedBytes: " + encryptedBytes.length);
        
                // print the encrypted message (in base64format String using Base64) 
                String dataEncrypted = Base64.getEncoder().encodeToString(encryptedBytes);
                System.out.println("Data encrypted: " + dataEncrypted);
                return dataEncrypted;
        } 

}

// RSA decryption
class RSADencrypt{
        public static String decrypt(InputStream inStream) throws Exception{
                // create data input stream from socket
                DataInputStream dis = new DataInputStream(inStream);
                
                // read server private key
                PrivateKey serverPrivateKey;
                serverPrivateKey = PrivateKeyReader.get("keys_certificate/private_key.der");
                System.out.println();
                System.out.println(serverPrivateKey);
                Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                desCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
                
                // decrypt message
                int len = dis.readInt();
                byte[] encryptedBytes = new byte[len];
                dis.readFully(encryptedBytes);
                byte[] decryptedBytesArray = desCipher.doFinal(encryptedBytes);

                String plainText = new String(decryptedBytesArray);
                System.out.println("plainText: " + plainText);

                return plainText;
        }
}