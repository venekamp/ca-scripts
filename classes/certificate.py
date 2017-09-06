import os
from pathlib import Path

from classes.ca import CA

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
