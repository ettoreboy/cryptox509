# cryptox509
A small java tool to create your own x509 signed certificate

## Build requirements
In order to build this tool from scratch, you will need:
* Apache Commons Codec 1.10
* BouncyCastle JCE for JDK 1.3

Already provided under /lib in this repository

## Usage
#### Generate a self signed certificate and the keys

``` bash
java -jar cryptox509.jar -g PATH/TO/config.properties
```
The configuration file must be a **.properties** file with the following mandatory fields

``` properties
#CONFIG EXAMPLE
Name = Ettore
StartDate = 16/06/2015 #Date format dd/MM/yyyy
EndDate =
Subject = Cryptox509
```
Date fields can be left empty, in that case the certificate will have a default **1 year** validity.
When executed, it will ask for a password in order to store the private key.
The tool will generate two files, the **JKS** keystore and a **PEM** readable certificate file.

####Check certificate validity
``` bash
java -jar cryptox509.jar -c PATH/TO/certificate PATH/TO/keystore.jks
```
