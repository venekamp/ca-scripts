import sys
import os
import click
import pkg_resources

#from classes.certficates import certificates

ca_globals = {}
caDir = os.path.abspath("ca")
certDir = os.path.abspath("client-certificates")

@click.group()
@click.option("-v", "--verbose", count=True, help="Set verbosity level.")
@click.option("--ca-dir", default=caDir,
              help="Set root direrectory of the CA. Defaults to: " + caDir)
@click.option("--certificate-dir", default=certDir,
              help="Set root direrectory of the certificates. Defaults to: " + certDir)
@click.version_option()
def cli(verbose, ca_dir, certificate_dir):
    ca_globals['verbose'] = verbose
    caDir = os.path.abspath(ca_dir)


@cli.command('create-key')
@click.option('--root-dir', default=certDir,
              help="Set the root directory where the keys and certificates are stored.")
@click.argument('fqdn')
def create_key(root_dir, fqdn):
    pass

@cli.command()
def version():
    """
      Show the version and exit.
    """
    exec_name    = os.path.basename(sys.argv[0])
    project_name = pkg_resources.require("ca-scripts")[0].project_name
    version      = pkg_resources.require("ca-scripts")[0].version

    click.echo(exec_name + " (" + project_name + "), version " + version)
