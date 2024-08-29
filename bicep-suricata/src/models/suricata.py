import asyncio
from  src.utils.models.ids_base import IDSBase
import shutil
import os
from ..utils.general_utilities import create_and_activate_network_interface,remove_network_interface,mirror_network_traffic_to_interface,execute_command, wait_for_process_completion
from ..utils.fastapi.utils import  send_alerts_to_core, send_alerts_to_core_periodically
from .suricata_parser import SuricataParser

class Suricata(IDSBase):
    configuration_location: str = "/tmp/suricata.yaml"
    log_location: str = "/opt/logs"
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
        self.tap_interface_name = f"tap{self.container_id}"
        await create_and_activate_network_interface(self.tap_interface_name)
        pid = await mirror_network_traffic_to_interface(default_interface="eth0", tap_interface=self.tap_interface_name)
        self.pids.append(pid)
        start_suricata = ["suricata", "-c", self.configuration_location, "-i", self.tap_interface_name, "-S", self.ruleset_location, "-l", self.log_location]
        pid = await execute_command(start_suricata)
        self.pids.append(pid)

        self.send_alerts_periodically_task = asyncio.create_task(send_alerts_to_core_periodically(ids=self))

        return f"started network analysis for container with {self.container_id}"
    
    async def startStaticAnalysis(self, file_path):
        command = ["suricata", "-c", self.configuration_location, "-S", self.ruleset_location,  "-r", file_path, "-l", self.log_location]
        pid = await execute_command(command)
        self.pids.append(pid)

        await wait_for_process_completion(pid)
        self.pids.remove(pid)
        if self.static_analysis_running:
            await send_alerts_to_core(ids=self)
        await self.stopAnalysis()            


    # overrides the default method
    async def stopAnalysis(self):
        from src.utils.fastapi.utils import tell_core_analysis_has_finished
        self.static_analysis_running = False
        await self.stop_all_processes()
        if self.send_alerts_periodically_task != None:            
            print(self.send_alerts_periodically_task)
            if not self.send_alerts_periodically_task.done():
                self.send_alerts_periodically_task.cancel()
            self.send_alerts_periodically_task = None
        print(self.tap_interface_name)
        if self.tap_interface_name != None:
            await remove_network_interface(self.tap_interface_name)
        await tell_core_analysis_has_finished(self)