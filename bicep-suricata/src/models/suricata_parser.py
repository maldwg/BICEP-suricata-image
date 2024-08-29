from src.utils.models.ids_base import IDSParser, Alert
import json
import os
import os.path
from datetime import datetime
from ..utils.general_utilities import ANALYSIS_MODES
class SuricataParser(IDSParser):

    # TODO: 10 scrape the whole directory  
    alert_file_location = "/opt/logs/alerts_and_anomalies.json"

    async def parse_alerts(self, analysis_mode: ANALYSIS_MODES,file_location=alert_file_location):
        
        parsed_lines = []
        if not os.path.isfile(file_location):
            return parsed_lines
        
        with open(file_location, "r") as file:
            for line in file:
                try:
                    line_as_json = json.loads(line)
                except:
                    print(f"could not parse line {line} \n ... skipping")
                    continue
                parsed_lines.append(await self.parse_line(line_as_json))

        # erase files content but do not delete the file itself
        open(file_location, 'w').close()
        return parsed_lines      

    async def parse_line(self, line):
        parsed_line = Alert()
        parsed_line.time = line.get("timestamp") 
        parsed_line.source = line.get("src_ip") + ":" + str(line.get("src_port"))
        parsed_line.destination = line.get("dest_ip") + ":" + str(line.get("dest_port"))
        parsed_line.type = line.get("event_type")


        # since different findings render different results, handle each type differently
        # severity from 1 to 3, 1 being the highest
        if parsed_line.type == "alert":
            parsed_line.message = line.get("alert").get("signature")
            parsed_line.severity = await self.normalize_threat_levels(line.get("alert").get("severity"))
        elif parsed_line.type == "anomaly":
            parsed_line.message = line.get("anomaly").get("event")
            # None, because for anomalys suricata does not provicde any details
            parsed_line.severity = None
        # since it is an array, acces the first element, then get the ip, the result is also in an array

        return parsed_line
    
    
    async def normalize_threat_levels(self, threat: int):
        # for suricata, 3 is the lowest threat level and 1 the highest 
        # --> 1 = 1 , 2 = 0.66, 3 = 0.33
        if threat is not None:
            if threat == 1:
                return 1.0
            elif threat == 2:
                return 0.66
            elif threat == 3:
                return 0.33
        return None