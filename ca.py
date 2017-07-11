import click
import os

from classes.ca import CA


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

"""Dictionary for keeping track of global variables."""
ca_globals = {
    'subdirs':                subdirs,
    'rootSerialFile':         '/serial',
    'rootConfig':             '/openssl.config',
    'rootKey':                subdirs['root_private']['path'] + '/ca-key.pem',
    'rootCertificate':        subdirs['root_certs']['path'] + '/ca-cert.pem',
    'intermediateSerialFile': subdirs['root_intermediate']['path'] + '/serial',
    'intermediateConfig':     subdirs['root_intermediate']['path'] + '/openssl.config',
    'intermediateKey':        subdirs['intermediate_private']['path'] + '/intermediate-key.pem',
    'intermediateCSR':        subdirs['intermediate_csr']['path'] + '/intermediate-csr.pem',
    'intermediateCert':       subdirs['intermediate_certs']['path'] + '/intermediate-cert.pem'
}


rootDir = os.path.abspath("ca")

@click.group()
@click.option("-v", "--verbose", count=True, help="Set verbosity level.")
@click.option("--root-dir", default="ca",
              help="Set root direrectory of the CA. Defaults to: ca")
@click.version_option()
def ca(verbose, root_dir):
    """CA management."""
    ca_globals['verbose'] = verbose
    rootDir = os.path.abspath(root_dir)


@ca.command(name='init')
@click.option('--serial-number', type=int, default=1000,
              metavar="<int>",
              help="Specify what the initial serial number should be.")
@click.argument('root-config-file', type=click.Path(exists=True),
                metavar="<root_config_file>")
@click.argument('intermediate-config-file', type=click.Path(exists=True),
                metavar="<intermediate_config_file>")
def ca_init(serial_number, root_config_file, intermediate_config_file):
    """
      Create a root directory if it does not exist and populate it. The
      init command requires one parameter:\n

      Args:\n
          CONFIG_FILE: path to the the configuration file of the root CA.
    """
    ca = CA(rootDir, ca_globals)
    ca.init(root_config_file, intermediate_config_file, serial_number)


@ca.command(name='create-root-key')
def ca_create_root_key():
    """
      Create a private key for the usage of the CA.
    """
    ca = CA(rootDir, ca_globals)
    ca.createRootKey()


@ca.command(name='create-intermediate-key')
def ca_create_intermediate_key():
    """
      Create a private key for the usage of the CA.
    """
    ca = CA(rootDir, ca_globals)
    ca.createIntermediateKey()



@ca.command(name='create-root-certificate')
def ca_create_root_certificate():
    """
      Create the root certificate for the CA.
    """
    ca = CA(rootDir, ca_globals)
    ca.createRootCertificate()


@ca.command(name='create-intermediate-certificate')
def create_intermediate_certificate():
    """
      Create a signed intermediate crtificate.
    """
    ca = CA(rootDir, ca_globals)
    ca.createIntermediateCertificate()


if __name__ == "__main__":
    ca()
