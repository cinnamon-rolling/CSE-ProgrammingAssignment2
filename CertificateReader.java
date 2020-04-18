import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.nio.file.Files;
import java.nio.file.Paths;

class CertificateReader {

    public static X509Certificate get(String filename) throws Exception {
        InputStream inputStream = new FileInputStream(filename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(inputStream);
    }
}