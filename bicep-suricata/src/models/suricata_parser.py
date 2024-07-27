from src.utils.models.ids_base import IDSParser, Alert
import json
import os
from datetime import datetime
class SuricataParser(IDSParser):

    # todo: 6 find location and how to fix it ?
    alertFileLocation = ""

    async def parse_alerts_from_network_traffic(self, file_location=alertFileLocation):
        
        parsed_lines = []

        with open(file_location, "r") as file:
            for line in file:
                line_as_json = json.loads(line)
                parsed_lines.append(self.parse_line(line_as_json))

        # remove file to prevent double sending results after next execution
        os.remove(file_location)

        return parsed_lines

    # TODO 11: Either refactor so that only one parse mtehod exists (botha re equivalent) or identify things that the modes seperate from each other
    async def parse_alerts_from_network_traffic(self, file_location=alertFileLocation):
        parsed_lines = []

        with open(file_location, "r") as file:
            for line in file:
                line_as_json = json.loads(line)
                parsed_lines.append(self.parse_line(line_as_json))

        # remove file to prevent double sending results after next execution
        os.remove(file_location)

        return parsed_lines
        

    async def parse_line(self, line):
        parsed_line = Alert()
        parsed_line.time = datetime.strptime(line.get("timestamp"), self.timestamp_format) 
        parsed_line.source = line.get("src_ip") + ":" + str(line.get("src_port"))
        parsed_line.destination = line.get("dest_ip") + ":" + str(line.get("dest_port"))
        parsed_line.type = line.get("event_type")


        # TODO 6: find out scale and adapt (0 to 1 or 0 to 10?)
        # since different findings render different results, handle each type differently
        if parsed_line.type == "alert":
            parsed_line.message = line.get("alert").get("signature")
            parsed_line.severity = line.get("alert").get("severity")
        elif parsed_line.type == "anomaly":
            parsed_line.message = line.get("anomaly").get("event")
            # None, because for anomalys suricata does not provicde any details
            parsed_line.severity = None
        # since it is an array, acces the first element, then get the ip, the result is also in an array



        return parsed_line