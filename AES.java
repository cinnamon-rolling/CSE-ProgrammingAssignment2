import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import javax.crypto.*;
import java.util.Base64;
import java.security.Key;
import javax.crypto.Cipher;

public class AES {

        // AES encrypt
        public static byte[] encrypt(byte[] byteArray, Key symmetricKey) throws Exception{
                // instantiate cipher
                Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                aesCipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
                
                // encrypt message
                byte [] encryptedBytesArray = aesCipher.doFinal(byteArray);
                // System.out.println("encryptedBytesArray: " + encryptedBytesArray + "\nLength of encryptedBytesArray: " + encryptedBytesArray.length);
                return encryptedBytesArray;
        }

        // AES decrypt
        public static byte[] decrypt(byte[] byteArray, Key symmetricKey) throws Exception{
                // instantiate cipher
                Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                aesCipher.init(Cipher.DECRYPT_MODE, symmetricKey);
                // decrypt message
                byte [] decryptedBytesArray = aesCipher.doFinal(byteArray);
                // System.out.println("decryptedBytesArray: " + decryptedBytesArray + "\nLength of decryptedBytesArray: "
                //                 + decryptedBytesArray.length);
                return decryptedBytesArray;
        }
}