package cryptox509;

/**
 *
 * @author Ettore Ciprian <cipettaro@gmail.com>
 */
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class CertificateGeneration {

    private static X509Certificate chain;
    private final Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);//Default start date
    private final Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);//Default expiration

    public static void main(String[] args) {

        try {
            //Generate ROOT certificate
            CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            keyGen.generate(1024);
            PrivateKey rootPrivateKey = keyGen.getPrivateKey();

            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=" + args[0]), (long) 365 * 24 * 60 * 60);

            rootCertificate = createSignedCertificate(rootCertificate, rootCertificate, rootPrivateKey);
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = rootCertificate;

            String alias = "mykey";
            char[] password = "password".toCharArray();
            String keystore = "testkeys.jks";

            //Store the certificate chain
            storeKeyAndCertificate(alias, password, keystore, rootPrivateKey, chain);
            //Reload the keystore and display key and certificate chain info
            loadAndDisplayChain(alias, password, keystore);
            //Clear the keystore
            clearKeyStore(alias, password, keystore);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static void storeKeyAndCertificate(String alias, char[] password, String keystore, Key key, X509Certificate[] chain) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(null, null);

        keyStore.setKeyEntry(alias, key, password, chain);
        keyStore.store(new FileOutputStream(keystore), password);
    }

    private static void loadAndDisplayChain(String alias, char[] password, String keystore) throws Exception {
        //Reload the keystore
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(keystore), password);

        Key key = keyStore.getKey(alias, password);

        if (key instanceof PrivateKey) {
            System.out.println("Get private key : ");
            System.out.println(key.toString());

            Certificate[] certs = keyStore.getCertificateChain(alias);
            System.out.println("Certificate chain length : " + certs.length);
            for (Certificate cert : certs) {
                System.out.println(cert.toString());
            }
        } else {
            System.out.println("Key is not private key");
        }
    }

    private static void clearKeyStore(String alias, char[] password, String keystore) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(keystore), password);
        keyStore.deleteEntry(alias);
        keyStore.store(new FileOutputStream(keystore), password);
    }

    private static X509Certificate createSignedCertificate(X509Certificate cetrificate, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) {
        try {
            Principal issuer = issuerCertificate.getSubjectDN();
            String issuerSigAlg = issuerCertificate.getSigAlgName();

            byte[] inCertBytes = cetrificate.getTBSCertificate();
            X509CertInfo info = new X509CertInfo(inCertBytes);
            info.set(X509CertInfo.ISSUER, new CertificateIssuerName((X500Name) issuer));

            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);

            return outCert;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private String convertCertificateToPEM(X509Certificate signedCertificate) throws IOException {
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(signedCertificate);
        return signedCertificatePEMDataStringWriter.toString();
    }

    /**
     * Read Config File
     *
     * @return Properties
     * @throws IOException
     */
    public Properties getPropValues() throws IOException {

        Properties prop = new Properties();
        String propFileName = "config.properties";

        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(propFileName);

        if (inputStream != null) {
            prop.load(inputStream);
        } else {
            throw new FileNotFoundException("property file '" + propFileName + "' not found in the classpath");
        }

        return prop;
    }

}
