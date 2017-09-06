import os
import sys
import click
import pkg_resources

from classes.ca import CA


ca_globals = {}
rootDir = os.path.abspath("ca")

@click.group()
@click.option("-v", "--verbose", count=True, help="Set verbosity level.")
@click.option("--root-dir", default="ca",
              help="Set root direrectory of the CA. Defaults to: ca")
@click.version_option()
def cli(verbose, root_dir):
    """
        CA management.
    """
    ca_globals['verbose']  = verbose
    ca_globals['root-dir'] = os.path.abspath(root_dir)


@cli.command(name='init')
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
    try:
        ca = CA(rootDir, ca_globals, True)
        ca.init(root_config_file, intermediate_config_file, serial_number)
    except FileNotFoundError as e:
        print (e)


@cli.command(name='create-root-key')
def ca_create_root_key():
    """
      Create a private key for the usage of the CA.
    """
    try:
        ca = getCA()
        ca.createRootKey()
    except FileExistsError as e:
        print(e)


@cli.command(name='create-intermediate-key')
def ca_create_intermediate_key():
    """
      Create a private key for the usage of the CA.
    """
    try:
        ca = getCA()
        ca.createIntermediateKey()
    except FileExistsError as e:
        print(e)


@cli.command(name='create-root-certificate')
def ca_create_root_certificate():
    """
      Create the root certificate for the CA.
    """
    try:
        ca = getCA()
        ca.createRootCertificate()
    except FileNotFoundError as e:
        print (e)


@cli.command(name='create-intermediate-certificate')
def create_intermediate_certificate():
    """
      Create a signed intermediate crtificate.
    """
    try:
        ca = getCA()
        ca.createIntermediateCertificate()
    except FileNotFoundError as e:
        print (e)


@cli.command(name='create-key')
@click.argument('fqdn')
def create_domain_key(fqdn):
    try:
        ca = getCA()
        ca.createDomainKey(fqdn)
     except FileNotFoundError as e:
        print (e)


@cli.command('sign-csr')
@click.argument('fqdn')
def sign_csr(fqdn):
    try:
        ca = getCA()
    except FileNotFoundError as e:
        print (e)

@CheckForPopulatedCAdirectory.command()
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
