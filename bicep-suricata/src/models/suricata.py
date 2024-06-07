from  src.utils.models.ids_base import IDSBase
from src.utils.fastapi.routes import tell_core_analysis_has_finished
import shutil
from ..utils.fastapi.utils import execute_command, wait_for_process_completion, stop_process

class Suricata(IDSBase):
    configuration_location: str = "/tmp/suricata.yaml"
    ruleset_location: str = "/tmp/custom_rules.rules"
    container_id: int = None
    pid: int = None

    async def configure(self, file_path):
        shutil.move(file_path, self.configuration_location)
        return "succesfully configured"
    
    async def configure_ruleset(self, file_path):
        shutil.move(file_path, self.ruleset_location)
        return "succesfuly setup ruleset"

    async def startNetworkAnalysis(self):
        return "Started Network analysis"
    
    async def startStaticAnalysis(self, file_path, container_id):
        self.container_id = container_id
        command = ["suricata", "-c", self.configuration_location, "-S", self.ruleset_location,  "-r", file_path]
        pid = await execute_command(command)
        self.pid = pid
        await wait_for_process_completion(pid)
        await self.stopAnalysis()            
    
    async def stopAnalysis(self):
        await stop_process(self.pid)
        self.pid = None
        await tell_core_analysis_has_finished(container_id=self.container_id)
