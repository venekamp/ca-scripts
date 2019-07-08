import os
import sys
import click
import pkg_resources
from pathlib import Path

from .ca import CA
from .ca import GlobalOptions

class Certificate:
    default_root_dir = os.path.abspath("client-certificates")

    subdirs = {
        'private':      { 'path': "/private", 'mode': 0o700 },
        'certificates': { 'path': "/certs",   'mode': 0o755 },
        'csr':          { 'path': "/csr",     'mode': 0o755 },
        'config':       { 'path': "/config",  'mode': 0o755 }
    }

    fqdn = None

    def __init__(self, global_options, fqdn=None, missing_ca_dir_okay=False):
        self.ca = CA(global_options, missing_ca_dir_okay=True)

        #  Add the root diretory to all paths
        if not global_options.root_dir:
            root_dir = os.path.abspath(self.default_root_dir)
        else:
            root_dir = global_options.root_dir

        for key, value in self.subdirs.items():
            self.subdirs[key] = { 'path': root_dir + value['path'], 'mode': value['mode'] }

        self.ca.subdirs = self.subdirs

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


    def init(self):
        self.ca.createDirectories()


verbose = False
root_dir = ""

@click.group()
@click.option("-v", "--verbose", count=True, help="Set verbosity level.")
# @click.option("--ca-dir", default=CA.default_root_dir,
#               help="Set root direrectory of the CA. Defaults to: " + CA.default_root_dir)
@click.option("--certificate-dir", default=Certificate.default_root_dir,
              help="Set root direrectory of the certificates. Defaults to: " + Certificate.default_root_dir)
@click.version_option()
@click.pass_context
# def cli(ctx, ca_dir, verbose, certificate_dir):
def cli(ctx, verbose, certificate_dir):
    ctx.obj = GlobalOptions(certificate_dir, verbose)


@cli.command('init')
# @click.option('--certificate_dir', default=Certificate.default_root_dir,
#               help="Set the root directory of the certificates. Defaults to: " + Certificate.default_root_dir)
@click.pass_obj
def init(global_options):
    try:
        certificate = Certificate(global_options, missing_ca_dir_okay=True)
        certificate.init()
    except FileNotFoundError as e:
        print (e)


@cli.command('create-key')
# @click.option('--ca-dir', default=None,
#               help="Set the root directory where the keys and certificates are stored.")
@click.option('--key-length', default=2048,
              help="Use the specified key length.")
@click.option('--pass-phrase/--no-pass-phrase', default=False,
              help="Ask for a pass phrase during key generation.")
@click.argument('fqdn')
@click.pass_obj
def create_key(global_options, key_length, pass_phrase, fqdn):
    """
      create a private key
    """
    cert = Certificate(global_options, fqdn)

    key = cert.getKeyName()
    cert.createKey(key, key_length, pass_phrase)


@cli.command('create-csr')
@click.option('--config', default=None,
              help="location of configuration file.")
@click.argument('fqdn')
# @click.option('--ca-dir', default=None,
#               help="Set the root directory where the keys and certificates are stored.")
@click.pass_obj
def create_csr(global_options, fqdn, config):
    """
      Create a certificate signing request (csr)
    """
    cert = Certificate(global_options, fqdn)

    key = cert.getKeyName()
    csr = cert.getCSRName()

    print("key: {}".format(key))
    print("csr: {}".format(csr))
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
