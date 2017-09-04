import os
import sys
import click
import pkg_resources

from classes.ca import CA
from classes.certificate import Certificate


cert_globals = {}


@click.group()
@click.option("-v", "--verbose", count=True, help="Set verbosity level.")
@click.option("--ca-dir", default=CA.default_root_dir,
              help="Set root direrectory of the CA. Defaults to: " + CA.default_root_dir)
@click.option("--certificate-dir", default=Certificate.default_root_dir,
              help="Set root direrectory of the certificates. Defaults to: " + Certificate.default_root_dir)
@click.version_option()
def cli(verbose, ca_dir, certificate_dir):
    cert_globals['verbose'] = verbose
    cert_globals['ca-dir']  = os.path.abspath(ca_dir)


@cli.command('create-key')
@click.option('--root-dir', default=None,
              help="Set the root directory where the keys and certificates are stored.")
@click.option('--key-length', default=2048,
              help="Use the specified key length.")
@click.option('--pass-phrase/--no-pass-phrase', default=False,
              help="Ask for a pass phrase during key generation.")
@click.argument('fqdn')
def create_key(root_dir, key_length, pass_phrase, fqdn):
    """
      create a private key
    """
    cert = Certificate(root_dir, cert_globals, fqdn)

    key = cert.getKeyName()
    cert.createKey(key, key_length, pass_phrase)


@cli.command('create-csr')
@click.argument('fdqn')
@click.option('--root-dir', default=None,
              help="Set the root directory where the keys and certificates are stored.")
def create_csr(root_dir, fqdn):
    """
      Create a certificate signing request (csr)
    """
    cert = Certificate(root_dir, fqdn)

    config = cert.getCSRName(root_dir, fqdn)
    key    = cert.getKeyName(root_dir, fqdn)
    csr    = cert.getCSRName(root_dir, fqdn)

    cert.createCSR(config, key, csr)


@cli.command()
def version():
    """
      Show the version and exit.
    """
    exec_name    = os.path.basename(sys.argv[0])
    project_name = pkg_resources.require("ca-scripts")[0].project_name
    version      = pkg_resources.require("ca-scripts")[0].version

    click.echo(exec_name + " (" + project_name + "), version " + version)
