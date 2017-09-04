import os
import subprocess
import click
import shutil
import errno

from enum import Enum
from pathlib import Path
from jinja2 import Template


class PathType(Enum):
    """
      Supports:
          file
          directory
    """
    file = 1
    directory = 2


class CA():
    default_root_dir = "ca"

    subdirs = {
        'root_certs':            { 'path': "/certs",                 'mode': 0o750 },
        'root_crl':              { 'path': "/crl",                   'mode': 0o750 },
        'root_newcerts':         { 'path': "/newcerts",              'mode': 0o750 },
        'root_private':          { 'path': "/private",               'mode': 0o700 },
        'root_intermediate':     { 'path': "/intermediate",          'mode': 0o750 },
        'intermediate_certs':    { 'path': "/intermediate/certs",    'mode': 0o750 },
        'intermediate_crl':      { 'path': "/intermediate/crl",      'mode': 0o750 },
        'intermediate_csr':      { 'path': "/intermediate/csr",      'mode': 0o750 },
        'intermediate_newcerts': { 'path': "/intermediate/newcerts", 'mode': 0o750 },
        'intermediate_private':  { 'path': "/intermediate/private",  'mode': 0o700 }
    }

    def __init__(self, rootDir, ca_globals, missing_ca_dir_okay=False):
        #  Add the root diretory to all paths
        if not rootDir:
            root_dir = os.path.abspath(self.default_root_dir)
        else:
            root_dir = rootDir

        for key, value in self.subdirs.items():
            value['path'] = root_dir + value['path']

        subdirs = self.subdirs

        self.rootConfigFile              = root_dir + '/openssl.config'
        self.rootIndex                   = root_dir + '/index.txt'
        self.rootSerialFile              = root_dir + '/serial'
        self.rootKey                     = subdirs['root_private']['path'] + '/ca-key.pem'
        self.rootKeyLength               = 4096
        self.rootCertificateFile         = subdirs['root_certs']['path'] + '/ca-certificate.pem'

        self.intermediateConfigFile      = subdirs['root_intermediate']['path'] + '/openssl.config'
        self.intermediateIndex           = root_dir + '/index.txt'
        self.intermediateSerialFile      = subdirs['root_intermediate']['path'] + '/serial'
        self.intermediateKey             = subdirs['intermediate_private']['path'] + '/intermediate-key.pem'
        self.intermediateKeyLength       = 4096
        self.intermediateCertificateFile = subdirs['intermediate_certs']['path'] + '/intermediate.pem'
        self.intermediateCSR             = subdirs['intermediate_csr']['path'] + '/intermediate-csr.pem'

        self.CAcertificateChain          = subdirs['intermediate_certs']['path'] + '/ca-chain-cert.pem'

        self.verbose                     = ca_globals['verbose']
        self.rootDir                     = root_dir
        self.intermediateDir             = subdirs['root_intermediate']['path']
        self.intermediatePrivate         = subdirs['intermediate_private']['path']

        if not missing_ca_dir_okay:
            self.CheckForPopulatedCAdirectory()


    def getIntermediateDirectory(self):
        return self.intermediateDir


    def CheckForPopulatedCAdirectory(self):
        if not Path(self.rootDir).exists():
            raise FileNotFoundError(errno.ENOENT, "Top level CA directory was not found",
                                    self.rootDir)
        try:
            self.CheckIfFileExists(self.rootConfigFile)
            self.CheckIfFileExists(self.rootIndex)
            self.CheckIfFileExists(self.rootSerialFile)

            self.CheckIfFileExists(self.intermediateConfigFile)
            self.CheckIfFileExists(self.intermediateIndex)
            self.CheckIfFileExists(self.intermediateSerialFile)

            for key, value in self.subdirs.items():
                self.CheckIfDirectoryExists(value['path'])

        except ValueError as e:
            print (e)


    def CheckIfFileExists(self, path):
        self.CheckIfPathExists(PathType.file, path)


    def CheckIfDirectoryExists(self, path):
        self.CheckIfPathExists(PathType.directory, path)


    def CheckIfPathExists(self, type, path):
        if not Path(path).exists():
            if type == PathType.file:
                raise FileNotFoundError(errno.ENOENT, "file not found", path)
            elif type == PathType.directory:
                raise FileNotFoundError(errno.ENOENT, "directory not found", path)
            else:
                raise ValueError


    def init(self, rootConfigTemplate, intermediateConfigTemplate,
             initialSerialNumber):
        try:
            self.createDirectories()
            self.createIndex()
            self.createInitialSerialNumbers(initialSerialNumber)
            self.copyConfiguration(rootConfigTemplate, self.rootConfigFile,
                                   {'root_path': self.rootDir})
            self.copyConfiguration(intermediateConfigTemplate,
                                   self.intermediateConfigFile,
                                   {'intermediate_path': self.intermediateDir,
                                    'intermediate_config': self.intermediateConfigFile})
        except FileExistsError:
            click.echo("Directory '%s' already exists. Skipping "
                       "initialization." % self.rootDir,
                       err=True)


    def createKey(self, key, keyLength, usePassPhrase=True):
        """
          Create a key.
        """
        if Path(key).exists():
            raise FileExistsError(errno.ENOENT, "Key already exists", key)

        if usePassPhrase:
            subprocess.run(["openssl", "genrsa",
                            "-aes256",
                            "-out", key, str(keyLength)],
                            check=True)
        else:
            subprocess.run(["openssl", "genrsa",
                            "-out", key, str(keyLength)],
                            check=True)
        os.chmod(key, 0o400)


    def createRootKey(self, usePassPhrase=True):
        try:
            self.createKey(self.rootKey, self.rootKeyLength, usePassPhrase)
        except FileExistsError as e:
            raise FileExistsError(e.errno, "Root key already exists", e.filename)


    def createCertificate(self, config, key, certificate, dayValid):
        subprocess.run(["openssl", "req", "-config", config,
                        "-key", key, "-new", "-x509",
                        "-days", str(dayValid), "-sha256",
                        "-extensions", "v3_ca", "-out", certificate])
        os.chmod(certificate, 0o444)


    def createRootCertificate(self, daysValid=7300):
        self.createCertificate(self.rootConfigFile, self.rootKey,
                               self.rootCertificateFile, daysValid)


    def createIntermediateKey(self, usePassPhrase=True):
        try:
            self.createKey(self.intermediateKey, self.intermediateKeyLength,
                           usePassPhrase)
        except FileExistsError as e:
            raise FileExistsError(e.errno, "Intermediate key already exists", e.filename)


    def createIntermediateCertificate(self):
        self.createCSR(self.intermediateConfigFile, self.intermediateKey,
                       self.intermediateCSR)
        self.signCSR(self.rootConfigFile, self.intermediateCSR,
                     self.intermediateCertificateFile)
        self.createIntermediateChain()


    def createCSR(self, config, key, csr):
        subprocess.run(["openssl", "req",
                        "-config", config,
                        "-new", "-sha256",
                        "-key", key,
                        "-out", csr])
        os.chmod(csr, 0o600)


    def signCSR(self, config, csr, certificate):
        subprocess.run(["openssl", "ca", "-config", config,
                        "-extensions", "v3_intermediate_ca",
                        "-days", "3650", "-notext", "-md", "sha256",
                        "-in", csr,
                        "-out", certificate])


    def createIndex(self):
        Path(self.rootIndex).touch(mode=0o600)
        Path(self.intermediateIndex).touch(mode=0o600)


    def createDirectories(self):
        """
          Create a number of directries and set the permissions for that
          directory.
        """
        os.makedirs(self.rootDir)
        if self.verbose > 0:
            click.secho("Created directory: " + self.rootDir)

        for key, subdir in self.subdirs.items():
            path = subdir['path']
            os.makedirs(path)
            os.chmod(path, subdir['mode'])
            if self.verbose > 0:
                click.secho("Created directory: " + subdir['path'])


    def createInitialSerialNumbers(self, serialNumber):
        """
          Create the serial files and put the initial serial number in it.
        """
        self.createSerialNumberFile( self.rootSerialFile, serialNumber )
        self.createSerialNumberFile( self.intermediateSerialFile, serialNumber )


    def createSerialNumberFile(self, filename, serialNumber):
        """
          Create a file and write the initial serial number in it

          Args:
              filename:     file name of the serial file.
              serialNumber: Initial serial number that will be written to
                            the file
        """
        with open(filename, 'w') as f:
            os.chmod(filename, 0o600)
            f.write(str(serialNumber))
        f.close()


    def copyConfiguration(self, src, dest, substitution):
        """
          Read the configuration file and substitute template parameters
          in it. Then write the result to the destination file.
        """
        with open(src) as f:
            configTemplate = f.read(100000)   # Read at max 100K characters
        f.close()

        template = Template(configTemplate)
        renderdConfig = template.render(substitution)

        with open(dest, "w") as f:
            f.write(renderdConfig)
        f.close()

        os.chmod(dest, 0o600)


    def createIntermediateChain(self):
        with open(self.CAcertificateChain, "wb") as f:
            self.concatenateFiles(self.intermediateCertificateFile, f)
            self.concatenateFiles(self.rootCertificateFile, f)
        f.close()

        os.chmod(self.CAcertificateChain, 0o444)


    def concatenateFiles(self, src, out):
        with open(src, "rb") as f:
            shutil.copyfileobj(f, out)
        f.close()


    def createDomainKey(self, fqdn):
        key = self.intermediatePrivate + fqdn
        self.createKey(key, 2048, False)
