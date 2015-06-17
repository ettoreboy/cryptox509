# cryptox509
A small java tool to create your own x509 signed certificate

## Build requirements
In order to build this tool, you will need:
* Apache Commons Codec 1.10
* BouncyCastle JCE for JDK 1.3

Already provided under /lib in this repository

## Usage
#### Generate a self signed certificate and the keys

``` bash
java -jar cryptox509.jar -g PATH/TO/config.properties
```
The configuration file must be a **.properties** file, formatted as follow:

``` properties
#CONFIG EXAMPLE
#Every field must be on the same line, newline at the end

#Issuer - the issuer of the certificate, can include specific fields separated by a comma (Country, State, Locality, Organization, Organization Unit, Common Name)
Issuer = C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server server-certs@thawte.com
#StartDate - start date (dd/MM/yyyy) of the certificate validity. Can be left blank, default value is the current system date.
StartDate = 16/06/2015
#EnDate - end date (dd/MM/yyyy) of validity. Can be left blank, default value is one year after startDate.
EndDate =
```
When executed, it will ask for a password in order to store the private key.
The tool will create two files, the **JKS** keystore and a readable **PEM** certificate file.

####Check certificate validity
``` bash
java -jar cryptox509.jar -c PATH/TO/certificate
```

## Download
A precompiled version can be found in [this repository](https://github.com/platinumjesus/cryptox509/blob/master/dist.zip?raw=true)

Under th folder /test there will be examples of a config file and certificate generated with this tool.
