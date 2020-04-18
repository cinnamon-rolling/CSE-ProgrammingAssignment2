import java.io.InputStream;
import java.security.*;
import java.security.PublicKey;
import javax.crypto.Cipher;

public class RSA{

        // RSA encrypt
        public static byte[] encrypt(byte[] byteArray, PublicKey serverPublicKey) throws Exception{
                // instantiate cypher
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

                // decrypt message
                byte[] encryptedBytesArray = rsaCipher.doFinal(byteArray);
                System.out.println("encryptedBytesArray: " + encryptedBytesArray + "\nLength of encryptedBytesArray: " + encryptedBytesArray.length);
        
                return encryptedBytesArray;
        } 

        // RSA decrypt
        public static byte[] decrypt(PrivateKey serverPrivateKey, byte[] byteArray, InputStream inStream) throws Exception{
                // instantiate cypher
                Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                desCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
                
                // decrypt message
                byte[] decryptedBytesArray = desCipher.doFinal(byteArray);
                System.out.println("decryptedBytesArray: " + decryptedBytesArray + "\nLength of decryptedBytesArray: " + decryptedBytesArray.length);

                return decryptedBytesArray;
        }

}