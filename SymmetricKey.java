import java.security.Key;
import javax.crypto.KeyGenerator;

public class SymmetricKey {
    public static Key getKey () throws Exception{
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);

        // generate a key
        Key key = generator.generateKey();
        System.out.println("Symmetric key: " + key);

        return key;
    }
}