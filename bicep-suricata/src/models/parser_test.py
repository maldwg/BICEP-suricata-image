import json
import os
from datetime import datetime
from abc import ABC, abstractmethod


class IDSParser(ABC):

    timestamp_format = '%Y-%m-%dT%H:%M:%S.%f%z'

    @property
    @abstractmethod
    def alertFileLocation(self):
        pass
    @abstractmethod
    def parse_alerts(self, file_location):
        """
        Method triggered once after the static analysis is complete or periodically for a network analysis. 
        Takes in the whole file, reads it, parses it, deletes it and returns the parsed lines
        """
        pass

    @abstractmethod
    def parse_line(self, line):
        """
        Method to parse one line at a time into the Alert object
        """
        pass

    @abstractmethod
    def normalize_threat_levels(self, threat: int):
        """
       Normalize the threat levels which are individual for each IDS from 0 to 1 (1 being the highest)
       returns decimal values with only 2 decimals
        """
        pass

class Alert():
    """
    Class which contains the most important fields of an alert (one line of anomaly).
    It presents a standardized interface for the different IDS to map their distinct alerts to.
    """
    time: datetime
    source: str
    destination: str
    severity: int
    type: str
    message: str

    def __str__(self):
        return f"{self.time}, From: {self.source}, To: {self.destination}, Type: {self.type}, Content: {self.message}, Severity: {self.severity}"

    def to_dict(self):
        return {
            # Convert datetime to ISO format string to be JSON serializable
            "time": self.time.isoformat(),  
            "source": self.source,
            "destination": self.destination,
            "severity": self.severity,
            "type": self.type,
            "message": self.message
        }



class SuricataParser(IDSParser):

    # TODO: 11 scrape the whole directory  
    alertFileLocation = "./suricata_alerts.json"

    def parse_alerts(self, file_location=alertFileLocation):
        
        parsed_lines = []

        with open(file_location, "r") as file:
            for line in file:
                line_as_json = json.loads(line)
                parsed_lines.append(self.parse_line(line_as_json))

        # remove file to prevent double sending results after next execution
        return parsed_lines      

    def parse_line(self, line):
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
    
    
    def normalize_threat_levels(self, threat: int):
        # for suricata, 3 is the lowest threat level and 1 the highest 
        # --> 1 = 1 , 2 = 0.66, 3 = 0.33
        if threat is not None:
            if threat == 1:
                return 1
            elif threat == 2:
                return 0.66
            elif threat == 3:
                return 0.33
            

if __name__ == "__main__":
    parser = SuricataParser()
    r: list[Alert] = parser.parse_alerts() 
    print(r[0])
    l = [a.to_dict() for a in r] 
    print(l[0])