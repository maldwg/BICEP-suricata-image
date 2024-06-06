from  src.utils.models.ids_base import IDSBase
from src.utils.fastapi.routes import tell_core_analysis_has_finished
import shutil
from ..utils.fastapi.utils import execute_command, wait_for_process_completion

class Suricata(IDSBase):
    configuration_location: str = "/tmp/suricata.yaml"
    ruleset_location: str = "/tmp/rules.yaml"
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
        # TODO: add config as well + ruleset?
        command = ["suricata", "-r", file_path]
        pid = await execute_command(command)
        self.pid = pid
        return_code = await wait_for_process_completion(pid)
        if return_code is not None:
            return f"Process with PID {pid} has exited with return code {return_code}"
        else:
            return f"Process with PID {pid} does not exist"
    
    async def stopAnalysis(self):
        # TODO: stop the process using the pid
        await tell_core_analysis_has_finished(container_id=self.container_id)
        return "Stopped analysis"

