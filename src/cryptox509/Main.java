package cryptox509;

import static cryptox509.Utilities.checkOwnerPassword;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 *
 * @author Ettore Ciprian <cipettaro@gmail.com>
 */
public class Main {
    private static CertificateGenerator gen;
    private static final String alias = "mykey";
    private static final String keystore = "keys.jks";
    
    public static void main(String[] args) {
            gen = init(args[0]);
        try {
            
            //Generate ROOT certificate
            CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            keyGen.generate(1024);
            PrivateKey rootPrivateKey = keyGen.getPrivateKey();

            long validity =  gen.getEndDate().getTime() - gen.getStartDate().getTime();
            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN="+gen.getIssuer()), gen.getStartDate(), validity/1000);
            rootCertificate = gen.createSignedCertificate(rootCertificate, rootCertificate, rootPrivateKey);
            
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = rootCertificate;
            
            char[] password = checkOwnerPassword();
            
            //Store the certificate to a pem file
            gen.storeKeyAndCertificate(alias, password, keystore, rootPrivateKey, chain);
            gen.printCertificateToPEM(rootCertificate, "cert.pem");
            //Reload the keystore and display key and certificate chain info
            gen.loadAndDisplay(alias, password, keystore);
            //Clear the keystore from certificate
            gen.clearKeyStore(alias, password, keystore);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

   private static CertificateGenerator init(String pathToConfig){
       
        if(Paths.get(pathToConfig).toFile().canRead()){
                return new CertificateGenerator(pathToConfig);
            }else{
                System.err.println(Paths.get(pathToConfig)+ " is not a valid path");
                System.err.println("Please provide a path to a valid config file");
                System.exit(-1);
                return null;
            }
        
       
   }
}
