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
    private static CertificateGenerator gen = new CertificateGenerator();
    private static final String alias = "mykey";
    private static final String keystore = "keys.jks";
    
    public static void main(String[] args) {
       
        switch (args[0]) {
            case "-g": 
                generateCert(args[1]);
             break;
             
            case "-c":
                if(Paths.get(args[1]).toFile().canRead()){
                gen.verifyCertificate(args[1]);
                }else{
                    System.err.println("Please provide a valid certificate path!");
                }
             break;
            default: System.err.println("Not a valid command.");
                     System.err.println("Possible usage:\n cryptox509.jar -g Path/to/config.properties.");
                     System.err.println("                  cryptox509.jar -c Path/to/certificate.");
                     System.exit(0);
        }
    }

    /**
     * Initialize the CertificateGenerator with the configuration file parameters
     * @param pathToConfig
     * @return 
     */
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
   
   /**
    * Generate a x509 v3 certificate
    * @param path 
    */
   private static void generateCert(String path){
           gen = init(path);
        try {
            
            //Generate ROOT certificate
            CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            keyGen.generate(1024);
            PrivateKey rootPrivateKey = keyGen.getPrivateKey();

            long validity =  gen.getEndDate().getTime() - gen.getStartDate().getTime();
            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name(gen.getIssuer()), gen.getStartDate(), validity/1000);
            rootCertificate = gen.createSignedCertificate(rootCertificate, rootCertificate, rootPrivateKey);
            
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = rootCertificate;
            
            char[] password = checkOwnerPassword();

            gen.storeKeyAndCertificate(alias, password, keystore, rootPrivateKey, chain);
            gen.printCertificateToPEM(rootCertificate, "cert.pem");
            gen.loadAndDisplay(alias, password, keystore);
            gen.clearKeyStore(alias, password, keystore);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
   }
}
