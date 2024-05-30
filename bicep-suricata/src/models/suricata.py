from  src.utils.models.ids_base import IDSBase

class Suricata(IDSBase):
    configuration_location = "/tmp/suricata.yaml"
    ruleset_location = "/tmp/rules.yaml"

    def configure(self):
        return "needs to be implemented suricata"