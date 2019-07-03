import os
import sys
import click
import pkg_resources
from pathlib import Path

from .ca import CA

class Certificate:
    default_root_dir = os.path.abspath("client-certificates")

    subdirs = {
        'private':      { 'path': "/private", 'mode': 0o700 },
        'certificates': { 'path': "/certs",   'mode': 0o755 },
        'csr':          { 'path': "/csr",     'mode': 0o755 },
        'config':       { 'path': "/config",  'mode': 0o755 }
    }

    fqdn = None

    def __init__(self, root_dir, cert_globals, fqdn):
        ca_globals = {}
        ca_globals['verbose'] = cert_globals['verbose']

        self.ca = CA(root_dir, ca_globals, True)

        if not root_dir:
            if os.path.isdir(os.path.abspath(self.default_root_dir)):
                root_dir = os.path.abspath(self.default_root_dir)
            else:
                try:
                    self.ca.CheckForPopulatedCAdirectory()

                    root_dir = self.ca.getIntermediateDirectory()
                except FileNotFoundError as e:
                    root_dir = Certificate.default_root_dir

        for key, value in self.subdirs.items():
            value['path'] = "{}/{}".format(root_dir, value['path'])

        Path(self.getPrivatePath()).mkdir(parents=True, exist_ok=True)
        Path(self.getCertsPath()).mkdir(parents=True, exist_ok=True)
        Path(self.getCSRPath()).mkdir(parents=True, exist_ok=True)

        self.fqdn = fqdn


    def getPrivatePath(self):
        return  self.subdirs['private']['path']


    def getCertsPath(self):
        return self.subdirs['certificates']['path']


    def getCSRPath(self):
        return self.subdirs['csr']['path']


    def getConfigName(self):
        """
          return the config name
        """
        return "{}/{}.config".format(self.subdirs['config']['path'], self.fqdn)


    def getKeyName(self):
        """
          return the key name
        """
        return "{}/{}.key".format(self.subdirs['private']['path'], self.fqdn)


    def getCSRName(self):
        """
          return the csr name
        """
        return "{}/{}.csr".format(self.subdirs['csr']['path'], self.fqdn)


    def createKey(self, key, keyLength, usePassPhrase):
        self.ca.createKey(key, keyLength, usePassPhrase)


    def createCSR(self, config, key, csr):
        self.ca.createCSR(config, key, csr)


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
@click.option('--config', default=None,
              help="location of configuration file.")
@click.argument('fqdn')
@click.option('--root-dir', default=None,
              help="Set the root directory where the keys and certificates are stored.")
def create_csr(root_dir, fqdn, config):
    """
      Create a certificate signing request (csr)
    """
    cert = Certificate(root_dir, cert_globals, fqdn)

    key    = cert.getKeyName()
    csr    = cert.getCSRName()

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
