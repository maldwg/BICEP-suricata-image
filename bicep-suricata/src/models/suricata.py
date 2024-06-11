from  src.utils.models.ids_base import IDSBase
from src.utils.fastapi.routes import tell_core_analysis_has_finished
import shutil
import os
from ..utils.fastapi.utils import execute_command, wait_for_process_completion, stop_process

class Suricata(IDSBase):
    configuration_location: str = "/tmp/suricata.yaml"
    log_location: str = "/opt/logs"
    container_id: int = None
    pid: int = None
    # the interface to listen on in network analysis modes
    network_interface = "eth0"

    # unique variables
    ruleset_location: str = "/tmp/custom_rules.rules"


    async def configure(self, file_path):
        shutil.move(file_path, self.configuration_location)
        try:
            os.mkdir(self.log_location)
            return "succesfully configured"
        except Exception as e:
            print(e)
            return e
        
    
    async def configure_ruleset(self, file_path):
        shutil.move(file_path, self.ruleset_location)
        return "succesfuly setup ruleset"

    async def startNetworkAnalysis(self, container_id):
        self.container_id = container_id

        # set network adapter to promiscuous mode
        command = ["ip", "link", "set", self.network_interface, "promisc", "on"]
        await execute_command(command)

        command = ["suricata", "-c", self.configuration_location, "-i", self.network_interface, "-l", self.log_location]
        pid = await execute_command(command)
        self.pid = pid
        return {"message": f"started network analysis for container with {container_id}"}
    
    async def startStaticAnalysis(self, file_path, container_id):
        self.container_id = container_id
        command = ["suricata", "-c", self.configuration_location, "-S", self.ruleset_location,  "-r", file_path, "-l", self.log_location]
        pid = await execute_command(command)
        self.pid = pid
        await wait_for_process_completion(pid)
        await self.stopAnalysis()            
    
    async def stopAnalysis(self):
        await stop_process(self.pid)
        self.pid = None
        await tell_core_analysis_has_finished(container_id=self.container_id)
