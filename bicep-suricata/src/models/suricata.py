import asyncio
from  src.utils.models.ids_base import IDSBase
import shutil
import os
from ..utils.general_utilities import create_and_activate_network_interface,remove_network_interface,mirror_network_traffic_to_interface,execute_command, wait_for_process_completion
from .suricata_parser import SuricataParser
import ruamel.yaml

class Suricata(IDSBase):
    configuration_location: str = "/tmp/suricata.yaml"
    log_location: str = "/opt/logs"
    # unique variables
    ruleset_location: str = "/tmp/custom_rules.rules"
    parser = SuricataParser()


    async def configure(self, file_path):
        shutil.move(file_path, self.configuration_location)
        self.tap_interface_name = f"tap{self.container_id}"
        await self.enhance_suricata_config_to_allow_for_ensemble()
        try:
            os.mkdir(self.log_location)
            return "succesfully configured"
        except Exception as e:
            print(e)
            return e
    
    async def configure_ruleset(self, file_path):
        shutil.move(file_path, self.ruleset_location)
        return "succesfuly setup ruleset"


    async def execute_network_analysis_command(self):
        start_suricata = ["suricata", "-c", self.configuration_location, "-i", self.tap_interface_name, "-S", self.ruleset_location, "-l", self.log_location]
        pid = await execute_command(start_suricata)
        return pid
    
    async def execute_static_analysis_command(self, file_path):
        command = ["suricata", "-c", self.configuration_location, "-S", self.ruleset_location,  "-r", file_path, "-l", self.log_location]
        pid = await execute_command(command)
        return pid

    async def enhance_suricata_config_to_allow_for_ensemble(self):
        # TODO 5: make more robust so that if key afp-packet not existing new config is added
        yaml = ruamel.yaml.YAML()
        with open(self.configuration_location, "r") as suricata_yaml:
            config = yaml.load(suricata_yaml)
            tap_interface_entry = {
                "interface": self.tap_interface_name,
                "cluster-id": self.container_id
            }
            config["af-packet"].append(tap_interface_entry)
        with open(self.configuration_location, "w") as suricata_yaml:
            yaml.dump(config, suricata_yaml)
