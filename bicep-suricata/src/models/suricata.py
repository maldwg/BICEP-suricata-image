from  src.utils.models.ids_base import IDSBase
from fastapi import UploadFile
import os
import shutil

# TODO: correct paths 
# TODO: what to do about rules?
class Suricata(IDSBase):
    configuration_location = "/tmp/suricata.yaml"
    ruleset_location = "/tmp/rules.yaml"

    def configure(self, temporary_file):
        shutil.move(temporary_file, self.configuration_location)
        return "succesfuly moved file"