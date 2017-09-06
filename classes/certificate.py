import os
from pathlib import Path

from classes.ca import CA

class Certificate:
    default_root_dir = os.path.abspath("client-certificates")

    root_dir = None
    fqdn = None

    def __init__(self, root_dir, cert_globals, fqdn):
        ca_globals = {}
        ca_globals['verbose'] = cert_globals['verbose']

        self.ca = CA(root_dir, ca_globals, True)

        if not root_dir:
            if os.path.isdir(os.path.abspath(self.default_root_dir)):
                self.root_dir = os.path.abspath(self.default_root_dir)
            else:
                try:
                    self.ca.CheckForPopulatedCAdirectory()

                    self.root_dir = self.ca.getIntermediateDirectory()
                except FileNotFoundError as e:
                    self.root_dir = Certificate.default_root_dir
        else:
            self.root_dir = root_dir

        Path(self.getPrivatePath(self.root_dir)).mkdir(parents=True, exist_ok=True)
        Path(self.getCertsPath(self.root_dir)).mkdir(parents=True, exist_ok=True)
        Path(self.getCSRPath(self.root_dir)).mkdir(parents=True, exist_ok=True)

        self.fqdn = fqdn


    def getPrivatePath(self, root_dir):
        return self.root_dir + "/private"


    def getCertsPath(self, root_dir):
        return self.root_dir + "/certs"


    def getCSRPath(self, root_dir):
        return self.root_dir + "/csr"


    def getConfigName(self):
        """
          return the config name
        """
        if not self.root_dir:
            raise TypeError("root_dir has not been assigned properly.")

        return self.root_dir + "/config/" + self.fqdn + ".config"


    def getKeyName(self):
        """
          return the key name
        """
        if not self.root_dir:
            raise TypeError("root_dir has not been assigned properly.")

        return self.root_dir + "/private/" + self.fqdn + ".key"


    def getCSRName(self):
        """
          return the csr name
        """
        if not self.root_dir:
            raise TypeError("root_dir has not been assigned properly.")

        return self.root_dir + "/csr/" + self.fqdn + ".csr"


    def createKey(self, key, keyLength, usePassPhrase):
        self.ca.createKey(key, keyLength, usePassPhrase)


    def createCSR(self, config, key, csr):
        self.ca.createCSR(config, key, csr)
