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
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Base64;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class CertificateGenerator {

    private String issuer;
    private Date startD, endD;
    private static X509Certificate chain;
    private final Date startDefault = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);//Default start date

    public CertificateGenerator(String path) {
        DateFormat format = new SimpleDateFormat("dd/MM/yyyy");
        try {
            Properties values = getProperties(path);//Get config file
            issuer = values.getProperty("Issuer");
            String start = values.getProperty("StartDate");
            String end = values.getProperty("EndDate");

            if (start == null || start.isEmpty()) {
                startD = startDefault;
            } else {
                startD = format.parse(start);
            }
            if (end == null || end.isEmpty() ) { 
                //Add one year to start date
                Calendar c = Calendar.getInstance();
                c.setTime(startD);
                c.add(Calendar.YEAR, 1);
                endD = c.getTime();
            }else {
                endD = format.parse(end);
            }
            System.out.println("########## Configuration loaded ##########");
            System.out.println("Issuer: "+issuer);
            System.out.println("Start Date: "+startD);
            System.out.println("End Date: "+endD);
            System.out.println("##########################################");

        } catch (ParseException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CertificateGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Date getStartDate() {
        return startD;
    }

    public void setStartDate(Date startD) {
        this.startD = startD;
    }

    public Date getEndDate() {
        return endD;
    }

    public void setEndDate(Date endD) {
        this.endD = endD;
    }

    public static X509Certificate getChain() {
        return chain;
    }

    public static void setChain(X509Certificate chain) {
        CertificateGenerator.chain = chain;
    }
    
    

    public void storeKeyAndCertificate(String alias, char[] password, String keystore, Key key, X509Certificate[] chain) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(null, null);

        keyStore.setKeyEntry(alias, key, password, chain);
        keyStore.store(new FileOutputStream(keystore), password);
    }
    
    /**
     * Load private key from the keystore
     * @param alias
     * @param password
     * @param keystore
     * @return
     * @throws Exception 
     */
    public Key loadKey(String alias, char[] password, String keystore) throws Exception {
        //Reload the keystore
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(keystore), password);

        Key key = keyStore.getKey(alias, password);

        if (key instanceof PrivateKey) {
            System.out.println("Private key parsed from keystore! ");
            System.out.println(Utilities.toHex(key.getEncoded()));
            return key;
        } else {
            System.err.println("Key is not the private key");
            return null;
        }
    }

    /**
     * Load and display cert and key from a keystore
     * @param alias
     * @param password
     * @param keystore
     * @throws Exception 
     */
    public void loadAndDisplay(String alias, char[] password, String keystore) throws Exception {
        //Reload the keystore
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(keystore), password);

        Key key = keyStore.getKey(alias, password);

        if (key instanceof PrivateKey) {
            System.out.println("Get private key : ");
            System.out.println(Utilities.toHex(key.getEncoded()));

            Certificate[] certs = keyStore.getCertificateChain(alias);
            System.out.println("Certificate chain length : " + certs.length);
            for (Certificate cert : certs) {
                System.out.println(cert.toString());
            }
        } else {
            System.err.println("Key is not the private key");
        }
    }

    /**
     * Clear key store form the certificate
     * @param alias
     * @param password
     * @param keystore
     * @throws Exception 
     */
    public void clearKeyStore(String alias, char[] password, String keystore) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(keystore), password);
        keyStore.deleteEntry(alias);
        keyStore.store(new FileOutputStream(keystore), password);
    }

    /**
     * Create a self signed certificate using the automatically generated key
     * @param cetrificate
     * @param issuerCertificate
     * @param issuerPrivateKey
     * @return 
     */
    public X509Certificate createSignedCertificate(X509Certificate cetrificate, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) {
        try {
            Principal CertIssuer = issuerCertificate.getSubjectDN();
            String issuerSigAlg = issuerCertificate.getSigAlgName();

            byte[] inCertBytes = cetrificate.getTBSCertificate();
            X509CertInfo info = new X509CertInfo(inCertBytes);
            info.set(X509CertInfo.ISSUER, new CertificateIssuerName((X500Name) CertIssuer));

            CertificateExtensions exts = new CertificateExtensions();
            BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
            exts.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(false, bce.getExtensionValue()));
            info.set(X509CertInfo.EXTENSIONS, exts);

            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);

            return outCert;
        } catch (CertificateException | IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException ex) {
        }
        return null;
    }

    /***
     * Convert to PEM format a valid X509Certificate
     * @param cert
     * @return
     * @throws CertificateEncodingException 
     */
    private static String convertToPem(X509Certificate cert) throws CertificateEncodingException {
        Base64 encoder = new Base64(64);
        String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        String end_cert = "-----END CERTIFICATE-----";

        byte[] derCert = cert.getEncoded();
        String pemCertPre = new String(encoder.encode(derCert));
        String pemCert = cert_begin + pemCertPre + end_cert;
        return pemCert;
    }

    /**
     * Write a X509 V3 certificate converted to PEM into a file
     * @param signedCertificate
     * @param path
     * @throws IOException 
     */
    public void printCertificateToPEM(X509Certificate signedCertificate, String path) throws IOException {
        String pem = "";
        try {
            pem = convertToPem(signedCertificate);
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(CertificateGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        try (PrintWriter writer = new PrintWriter(path, "UTF-8")) {
            System.out.println(pem);
            writer.print(pem);
            writer.close();
        } catch (FileNotFoundException | UnsupportedEncodingException ex) {
            System.err.println("Please provide a valid path");
        }

    }

    /**
     * Read configuration file.
     * Must be in the same folder as the jar file, named 'config.properties'.
     *
     * @return Properties
     * @throws IOException
     */
    private Properties getProperties(String path) throws IOException {

        Properties prop = new Properties();
        String propFileName = "config.properties";
       
        InputStream inputStream = new FileInputStream(path);
        
        if (inputStream != null) {
            prop.load(inputStream);
        } else {
            throw new FileNotFoundException("Property file '" + propFileName + "' not found in current folder");
        }

        return prop;
    }

}
