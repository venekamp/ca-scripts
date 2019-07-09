import os
import sys
import subprocess
import click
import shutil
import errno
import tarfile

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
        'intermediate_private':  { 'path': "/intermediate/private",  'mode': 0o700 },
        'intermediate_config':   { 'path': "/intermediate/config",   'mode': 0o700 }
    }

    files = {
        'rootConfig':         "/openssl.config",
        'rootIndex':          "/index.txt",
        'rootSerial':         "/serial",
        'rootKey':            "{}/ca-key.pem".format(subdirs['root_private']['path']),
        'rootCertificate':    "{}/ca-certificate.pem".format(subdirs['root_certs']['path']),

        'intermediateConfig':      "{}/openssl.config".format(subdirs['root_intermediate']['path']),
        'intermediateIndex':       "{}/index.txt".format(subdirs['root_intermediate']['path']),
        'intermediateSerial':      "{}/serial".format(subdirs['root_intermediate']['path']),
        'intermediateKey':         "{}/intermediate-key.pem".format(subdirs['intermediate_private']['path']),
        'intermediateCertificate': "{}/intermediate-ca.pem".format(subdirs['intermediate_certs']['path']),
        'intermediateCSR':         "{}/intermediate-csr.pem".format(subdirs['intermediate_csr']['path']),

        'CAcertificateChain':      "{}/ca-chain-cert.pem".format(subdirs['intermediate_certs']['path'])
    }

    def __init__(self, global_options, fqdn=None, missing_ca_dir_okay=False):
        self.fqdn = fqdn

        #  Add the root diretory to all paths
        if not global_options.root_dir:
            root_dir = os.path.abspath(self.default_root_dir)
        else:
            root_dir = global_options.root_dir

        for key, value in self.subdirs.items():
            self.subdirs[key] = { 'path': root_dir + value['path'], 'mode': value['mode'] }

        for key, value in self.files.items():
            self.files[key] = root_dir + value

        self.rootKeyLength         = 4096
        self.intermediateKeyLength = 4096
        self.verbose_level         = global_options.verbose_level
        self.rootDir               = root_dir

        if not missing_ca_dir_okay:
            self.CheckForPopulatedCAdirectory()


    def getIntermediateDirectory(self):
        return self.subdirs['root_intermediate']['path']


    def getIntermediateConfigName(self):
        return self.files['intermediateConfig']


    def getConfigName(self):
        return "{}/{}.config".format(self.subdirs['intermediate_config']['path'],
                                  self.fqdn)


    def getCSRName(self):
        return "{}/{}.csr".format(self.subdirs['intermediate_csr']['path'],
                                  self.fqdn)


    def getCertificateName(self):
        return "{}/{}.pem".format(self.subdirs['intermediate_newcerts']['path'],
                                  self.fqdn)


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

        if config and os.path.exists(config):
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
        if self.verbose_level > 0:
            click.secho("Created directory: " + self.rootDir)

        for key, subdir in self.subdirs.items():
            path = subdir['path']
            os.makedirs(path)
            os.chmod(path, subdir['mode'])
            if self.verbose_level > 0:
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
        key = "{}/{}.key".format(self.subdirs['intermediatPrivate']['path'],
                                 fqdn)
        self.createKey(key, 2048, False)


    def getCerts(self):
        archive_name = self.fqdn + ".tb2"

        with tarfile.open(archive_name, "w:bz2") as tar:
            if self.verbose_level > 0:
                click.secho("Creating archive: {}".format(archive_name))
            files = [
                {
                    "path": self.files['CAcertificateChain'],
                    "alternative": "chain.pem"
                },
                {
                    "path": self.subdirs["intermediate_newcerts"]["path"] + "/" + self.fqdn + ".pem",
                    "alternative": self.fqdn + ".pem"
                }
            ]
            for name in files:
                if self.verbose_level > 1:
                    click.secho("Adding to archive: {} as {}".format(name["path"], name["alternative"]))

                tar.add(name["path"], name["alternative"])

        if self.verbose_level > 0:
            click.secho("Done")


class GlobalOptions:
    def __init__(self, root_dir, verbose_level):
        self.root_dir = root_dir
        self.verbose_level = verbose_level


@click.group()
@click.option("-v", "--verbose", count=True, help="Set verbosity level.")
@click.option("--ca-dir", default="ca",
              help="Set root direrectory of the CA. Defaults to: ca")
@click.version_option()
@click.pass_context
def cli(ctx, verbose, ca_dir):
    """
        CA management.
    """
    ctx.obj = GlobalOptions(ca_dir, verbose)


@cli.command(name='init')
@click.option('--serial-number', type=int, default=1000,
              metavar="<int>",
              help="Specify what the initial serial number should be.")
@click.argument('root-config-file', type=click.Path(exists=True),
                metavar="<root_config_file>")
@click.argument('intermediate-config-file', type=click.Path(exists=True),
                metavar="<intermediate_config_file>")
@click.pass_obj
def ca_init(global_options, serial_number, root_config_file, intermediate_config_file):
    """
      Create a root directory if it does not exist and populate it. The
      init command requires one parameter:\n

      Args:\n
          CONFIG_FILE: path to the the configuration file of the root CA.
    """
    try:
        ca = CA(global_options, missing_ca_dir_okay=True)
        ca.init(root_config_file, intermediate_config_file, serial_number)
    except FileNotFoundError as e:
        print (e)


@cli.command(name='create-root-key')
@click.pass_obj
def ca_create_root_key(global_options):
    """
      Create a private key for the usage of the CA.
    """
    try:
        ca = CA(global_options)
        ca.createRootKey()
    except FileExistsError as e:
        print(e)


@cli.command(name='create-intermediate-key')
@click.pass_obj
def ca_create_intermediate_key(global_options):
    """
      Create a private key for the usage of the CA.
    """
    try:
        ca = CA(global_options)
        ca.createIntermediateKey()
    except FileExistsError as e:
        print(e)


@cli.command(name='create-root-certificate')
@click.pass_obj
def ca_create_root_certificate(global_options):
    """
      Create the root certificate for the CA.
    """
    try:
        ca = CA(global_options)
        ca.createRootCertificate()
    except FileNotFoundError as e:
        print(e)


@cli.command(name='create-intermediate-certificate')
@click.pass_obj
def create_intermediate_certificate(global_options):
    """
      Create a signed intermediate crtificate.
    """
    try:
        ca = CA(global_options)
        ca.createIntermediateCertificate()
    except FileNotFoundError as e:
        print(e)


@cli.command(name='create-key')
@click.argument('fqdn')
@click.pass_obj
def create_domain_key(global_options, fqdn):
    try:
        ca = CA(global_options)
        ca.createDomainKey(fqdn)
    except FileNotFoundError as e:
        print(e)


@cli.command('sign-csr')
@click.argument('csr-file')
@click.argument('fqdn')
@click.pass_obj
def sign_csr(global_options, csr_file, fqdn):
    try:
        ca = CA(global_options, fqdn)

        config      = ca.getIntermediateConfigName()
        certificate = ca.getCertificateName()

        ca.signCSR(config, csr_file, certificate)
    except FileNotFoundError as e:
        print(e)


@cli.command('get-certs')
@click.argument('fqdn')
@click.pass_obj
def get_certs(global_options, fqdn):
    ca = CA(global_options, fqdn)

    ca.getCerts()


@cli.command()
def version():
    """
      Show the version and exit.
    """
    exec_name    = os.path.basename(sys.argv[0])
    project_name = pkg_resources.require("ca-scripts")[0].project_name
    version      = pkg_resources.require("ca-scripts")[0].version

    click.echo(exec_name + " (" + project_name + "), version " + version)


if __name__ == "__main__":
    pass
