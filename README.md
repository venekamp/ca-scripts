ca-scripts
===

*Creating your own Certificate Authority.*

# About
The `ca-scripts` package contains two command line tools that help to
create and maintain a CA setup and to enable the creation and signing
of server certificates. These two tools are:
- ca
- certificate
Both support the `--help` option for additional information about
supported commands. The former contains functionality from the
perspective of a certificate authority, while the latter takes the
viewpoint of a user wanting a certificate.

## Root and Intermediate CA
The setup of the CA is twofold. First a root CA is needed and then an
intermediate CA is created, which is signed by the root CA. When users
need a signed certificate, it is the intermediate CA that is being used
for that.

## Install
[todo]

## Examples

### Initial setup
Creating a CA start with creating and initializing a number of
directories and files.
```bash
ca init <root_config_file> <intermediate_config_file>
```

### Create the root key
First step after having the correct directory structure and initialized
files is to create a private key for the CA.
```
ca create-root-key
```

### Create the root certificate
Once the root key has been created, a root certificate can be rendered.
```bash
ca create-root-certificate
```

### Create the intermediate key
Now that the root CA has been created, the same steps needs to be
performed for the intermediate CA.
```bash
ca create-intermediate-key
```

### Create the intermediate certificate
Having a private key for the intermediate CA, a certificate for that
intermediate CA can be created.
```bash
ca create-intermediate-certificate
```
This command start with creating a certificate signing request (csr),
which is then signed by the root CA. This results in a certificate for
the intermediate CA.

### Create a server key
When creating a server certificate, a private key needs to be created
first. This step is considered not to be responsibility of the CA.
Therefore, the `ca` command is not used. It is the responsibility of the
user to create a csr that can be signed by the CA.
```bash
certificate create-key <fqdn>
```
Here, `<fqdn>` must be the server name, and it must be specified as a
Fully Quantified Domain Name (FQDN).

### Create a server certificate sign request (csr)
The user must then create the csr that the CA needs to sign.
```bash
certificate create-csr <fqdn>
```
Of course the `<fqdn>` for this step should be the same as in the
previous step.

### Create a server certificate, i.e. sign a csr
Now that the user has created his csr and has sent it over to the CA,
the CA needs to sign it,
```bash
ca sign-csr <fqdn>
```

### Package server certificate and CA certificate chain
Not implemented yet
