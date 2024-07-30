from src.utils.models.ids_base import IDSParser, Alert
import json
import os
from datetime import datetime
class SuricataParser(IDSParser):

    # todo: 11 scrape the whole directory  
    alertFileLocation = "/opt/logs/alerts_and_anomalies.json"

    async def parse_alerts(self, file_location=alertFileLocation):
        
        parsed_lines = []

        with open(file_location, "r") as file:
            for line in file:
                line_as_json = json.loads(line)
                parsed_lines.append(await self.parse_line(line_as_json))

        # remove file to prevent double sending results after next execution
        os.remove(file_location)

        return parsed_lines      

    async def parse_line(self, line):
        parsed_line = Alert()
        parsed_line.time = datetime.strptime(line.get("timestamp"), self.timestamp_format) 
        parsed_line.source = line.get("src_ip") + ":" + str(line.get("src_port"))
        parsed_line.destination = line.get("dest_ip") + ":" + str(line.get("dest_port"))
        parsed_line.type = line.get("event_type")


        # since different findings render different results, handle each type differently
        # severity from 1 to 3, 1 being the highest
        if parsed_line.type == "alert":
            parsed_line.message = line.get("alert").get("signature")
            parsed_line.severity = self.normalize_threat_levels(line.get("alert").get("severity"))
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
                return 1
            elif threat == 2:
                return 0.66
            elif threat == 3:
                return 0.33