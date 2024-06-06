from  src.utils.models.ids_base import IDSBase
from src.utils.fastapi.routes import tell_core_analysis_has_finished
import shutil

# TODO: correct paths 
# TODO: what to do about rules?
class Suricata(IDSBase):
    configuration_location: str = "/tmp/suricata.yaml"
    ruleset_location: str = "/tmp/rules.yaml"
    container_id: int = None

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
        return "Started Static Analysis"
    
    async def stopAnalysis(self):
        await tell_core_analysis_has_finished(container_id=self.container_id)
        return "Stopped analysis"
