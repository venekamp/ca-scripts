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

    files = {
        'rootConfig':         "/openssl.config",
        'rootIndex':          "/index.txt",
        'rootSerial':         "/serial",
        'rootKey':            "{}/ca-key.pem".format(subdirs['root_private']['path']),
        'rootCertificate':    "{}/ca-certificate.pem".format(subdirs['root_certs']['path']),

        'intermediateConfig':      "{}/openssl.config".format(subdirs['root_intermediate']['path']),
        'intermediateIndex':       "{}/index".format(subdirs['root_intermediate']['path']),
        'intermediateSerial':      "{}/serial".format(subdirs['root_intermediate']['path']),
        'intermediateKey':         "{}/intermediate-key.pem".format(subdirs['intermediate_private']['path']),
        'intermediateCertificate': "{}/intermediate.pem".format(subdirs['intermediate_private']['path']),
        'intermediateCSR':         "{}/intermediate-csr.pem".format(subdirs['intermediate_csr']['path']),

        'CAcertificateChain':      "{}/ca-chain-cert.pem".format(subdirs['intermediate_certs']['path'])
    }

    def __init__(self, rootDir, ca_globals, fqdn=None, missing_ca_dir_okay=False):
        self.fqdn = fqdn

        #  Add the root diretory to all paths
        if not rootDir:
            root_dir = os.path.abspath(self.default_root_dir)
        else:
            root_dir = rootDir

        for key, value in self.subdirs.items():
            value['path'] = root_dir + value['path']

        for key, value in self.files.items():
            self.files[key] = root_dir + value

        self.rootKeyLength               = 4096
        self.intermediateKeyLength       = 4096
        self.verbose                     = ca_globals['verbose']
        self.rootDir                     = root_dir

        if not missing_ca_dir_okay:
            self.CheckForPopulatedCAdirectory()


    def getIntermediateDirectory(self):
        return self.intermediateDir


    def getCSR(self):
        if self.fqdn:
            return self.intermediateCSR + "/" + self.fqdn + ".csr"


    def CheckForPopulatedCAdirectory(self):
        if not Path(self.rootDir).exists():
            raise FileNotFoundError(errno.ENOENT, "Top level CA directory was not found",
                                    self.rootDir)
        try:
            self.CheckIfFileExists(self.files['rootConfig'])
            self.CheckIfFileExists(self.files['rootIndex'])
            self.CheckIfFileExists(self.files['rootSerial'])

            self.CheckIfFileExists(self.files['intermediateConfig'])
            self.CheckIfFileExists(self.files['intermediateIndex'])
            self.CheckIfFileExists(self.files['intermediateSerial'])

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
            self.copyConfiguration(rootConfigTemplate, self.files['rootConfig'],
                                   {'root_path': self.rootDir})
            self.copyConfiguration(intermediateConfigTemplate,
                                   self.files['intermediateConfig'],
                                   {'intermediate_path': self.subdirs['root_intermediate']['path'],
                                    'intermediate_config': self.files['intermediateConfig']})
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
            self.createKey(self.files['rootKey'], self.rootKeyLength, usePassPhrase)
        except FileExistsError as e:
            raise FileExistsError(e.errno, "Root key already exists", e.filename)


    def createCertificate(self, config, key, certificate, dayValid):
        subprocess.run(["openssl", "req", "-config", config,
                        "-key", key, "-new", "-x509",
                        "-days", str(dayValid), "-sha256",
                        "-extensions", "v3_ca", "-out", certificate])
        os.chmod(certificate, 0o444)


    def createRootCertificate(self, daysValid=7300):
        self.createCertificate(self.files['rootConfig'], self.files['rootKey'],
                               self.files['rootCertificate'], daysValid)


    def createIntermediateKey(self, usePassPhrase=True):
        try:
            self.createKey(self.files['intermediateKey'], self.intermediateKeyLength,
                           usePassPhrase)
        except FileExistsError as e:
            raise FileExistsError(e.errno, "Intermediate key already exists", e.filename)


    def createIntermediateCertificate(self):
        self.createCSR(self.files['intermediateConfig'], self.files['intermediateKey'],
                       self.files['intermediateCSR'])
        self.signCSR(self.files['rootConfig'], self.files['intermediateCSR'],
                     self.files['intermediateCertificate'])
        self.createIntermediateChain()


    def createCSR(self, config, key, csr):
        openssl = ["openssl", "req"]

        if config:
            openssl.extend(["-config", config])

        openssl.extend(["-new", "-sha256",
                        "-key", key,
                        "-out", csr])

        subprocess.run(openssl)
        os.chmod(csr, 0o600)


    def signCSR(self, config, csr, certificate):
        openssl = ["openssl", "ca"]

        if config:
            openssl.extend(["-config", config])

        openssl.extend(["-extensions", "v3_intermediate_ca",
                        "-days", "3650", "-notext", "-md", "sha256",
                        "-in", csr,
                        "-out", certificate])

        subprocess.run(openssl)


    def createIndex(self):
        Path(self.files['rootIndex']).touch(mode=0o600)
        Path(self.files['intermediateIndex']).touch(mode=0o600)


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
        self.createSerialNumberFile(self.files['rootSerial'], serialNumber)
        self.createSerialNumberFile(self.files['intermediateSerial'], serialNumber)


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
        with open(self.files['CAcertificateChain'], "wb") as f:
            self.concatenateFiles(self.files['intermediateCertificate'], f)
            self.concatenateFiles(self.files['rootCertificate'], f)
        f.close()

        os.chmod(self.files['CAcertificateChain'], 0o444)


    def concatenateFiles(self, src, out):
        with open(src, "rb") as f:
            shutil.copyfileobj(f, out)
        f.close()


    def createDomainKey(self, fqdn):
        key = self.intermediatePrivate + fqdn
        self.createKey(key, 2048, False)
