import asyncio
from src.utils.models.ids_base import IDSBase
import shutil
import os
from ..utils.general_utilities import (
    exececute_command_sync_in_seperate_thread,
    execute_command_async,
)
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
        try:
            os.makedirs(self.log_location, exist_ok=True)
            await self.enhance_suricata_config_to_allow_for_ensemble()
            return "succesfully configured"
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="Exception occured occured while configuring suricata. Please check the confgiuration file again and make sure it is valid!",
            )

    async def configure_ruleset(self, file_path):
        shutil.move(file_path, self.ruleset_location)
        return "succesfuly setup ruleset"

    async def execute_network_analysis_command(self):
        command = [
            "suricata",
            "-c",
            self.configuration_location,
            "-i",
            self.tap_interface_name,
            "-S",
            self.ruleset_location,
            "-l",
            self.log_location,
        ]
        pid = await execute_command_async(command)
        return pid

    async def execute_static_analysis_command(self, file_path):
        command = [
            "suricata",
            "-c",
            self.configuration_location,
            "-S",
            self.ruleset_location,
            "-r",
            file_path,
            "-l",
            self.log_location,
        ]
        pid = await execute_command_async(command)
        return pid

    async def enhance_suricata_config_to_allow_for_ensemble(self):
        # TODO 5: make more robust so that if key afp-packet not existing new config is added
        yaml = ruamel.yaml.YAML()
        with open(self.configuration_location, "r") as suricata_yaml:
            config = yaml.load(suricata_yaml)
            tap_interface_entry = {
                "interface": self.tap_interface_name,
                "cluster-id": self.container_id,
            }
            config["af-packet"].append(tap_interface_entry)
        with open(self.configuration_location, "w") as suricata_yaml:
            yaml.dump(config, suricata_yaml)
