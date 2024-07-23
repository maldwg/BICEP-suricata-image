import asyncio
from  src.utils.models.ids_base import IDSBase
import shutil
import os
from ..utils.fastapi.utils import execute_command, wait_for_process_completion, stop_process
from .suricata_parser import SuricataParser
from ..utils.models.ids_base import Alert

class Suricata(IDSBase):
    configuration_location: str = "/tmp/suricata.yaml"
    log_location: str = "/opt/logs"
    pid: int = None
    send_alerts_task = None
    # the interface to listen on in network analysis modes
    network_interface = "eth0"

    # unique variables
    ruleset_location: str = "/tmp/custom_rules.rules"
    parser = SuricataParser()

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

    async def startNetworkAnalysis(self):
        # set network adapter to promiscuous mode
        command = ["ip", "link", "set", self.network_interface, "promisc", "on"]
        await execute_command(command)

        command = ["suricata", "-c", self.configuration_location, "-i", self.network_interface, "-l", self.log_location]
        pid = await execute_command(command)
        self.pid = pid

        self.send_alerts_task = asyncio.create_task(self.parser.parse_alerts_from_network_traffic())

        return f"started network analysis for container with {self.container_id}"
    
    async def startStaticAnalysis(self, file_path):
        from src.utils.fastapi.routes import send_alerts_to_core
        command = ["suricata", "-c", self.configuration_location, "-S", self.ruleset_location,  "-r", file_path, "-l", self.log_location]
        pid = await execute_command(command)
        self.pid = pid
        await wait_for_process_completion(pid)
        alerts: list[Alert] = await self.parser.parse_alerts_from_file()
        await send_alerts_to_core(ids=self, alerts=alerts, analysis_type="static")
        await self.stopAnalysis()            


    # overrides the default method
    async def stopAnalysis(self):
        from src.utils.fastapi.utils import stop_process
        from src.utils.fastapi.routes import tell_core_analysis_has_finished

        await stop_process(self.pid)
        await self.send_alerts_task.cancel()
        self.pid = None
        await tell_core_analysis_has_finished(self)