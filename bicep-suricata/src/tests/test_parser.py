import pytest
import json
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import Response
from src.utils.models.ids_base import Alert
from src.models.suricata import SuricataParser
import shutil
import json
import tempfile
from pathlib import Path
import os


TEST_FILE_LOCATION = "bicep-suricata/src/tests/testfiles"

@pytest.fixture
def parser():
    parser = SuricataParser()
    parser.alert_file_location = TEST_FILE_LOCATION
    return parser

@pytest.mark.asyncio
async def test_parse_alerts_empty_file(parser: SuricataParser):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        parser.alert_file_location = temp_file.name
    alerts = await parser.parse_alerts()
    assert alerts == [], "Expected empty list for an empty log file"


@pytest.mark.asyncio
async def test_parse_alerts_valid_and_invalid_data(parser: SuricataParser):
    original_alert_file = f"{TEST_FILE_LOCATION}/test_alerts_and_anomalies.json"
    temporary_alert_file = f"{TEST_FILE_LOCATION}/test_alerts_and_anomalies_temporary.json"
    shutil.copy(original_alert_file, temporary_alert_file)
    parser.alert_file_location = temporary_alert_file
    print(parser.alert_file_location)
    alerts = await parser.parse_alerts()
    
    # there are 384 entries that should be regarded as valid
    assert len(alerts) == 384
    assert alerts[0].message == "decoder.ipv6.zero_len_padn"
    assert alerts[0].severity == None
    assert alerts[100].message == "SURICATA TCPv4 invalid checksum"
    assert alerts[383].severity == 0.33 

    os.remove(temporary_alert_file)



@pytest.mark.asyncio
async def test_parse_line_valid_anomaly(parser: SuricataParser):
    line_data = {
        "timestamp":"2017-07-07T09:00:34.000000+0000",
        "pcap_cnt":158,
        "event_type":"anomaly",
        "src_ip":"192.168.10.9",
        "src_port":0,
        "dest_ip":"224.0.0.22",
        "dest_port":0,
        "proto":"IGMP",
        "pkt_src":"wire/pcap",
        "anomaly":{
            "type":"decode",
            "event":"decoder.ipv4.opt_pad_required"
        }       
     }
    
    alert = await parser.parse_line(line_data)
    
    assert isinstance(alert, Alert)
    assert alert.message == "decoder.ipv4.opt_pad_required"
    assert alert.severity == None



@pytest.mark.asyncio
async def test_parse_line_valid_alert(parser: SuricataParser):
    # original data
    line_data = {
        "timestamp":"2017-07-07T09:00:35.000000+0000",
        "flow_id":844425276156800,
        "pcap_cnt":347,
        "event_type":"alert",
        "src_ip":"192.168.10.9",
        "src_port":1033,
        "dest_ip":"192.168.10.3",
        "dest_port":88,
        "proto":"TCP",
        "pkt_src":"wire/pcap",
        "alert":{
            "action":"allowed",
            "gid":1,
            "signature_id":2200074,
            "rev":2,
            "signature":"SURICATA TCPv4 invalid checksum",
            "category":"Generic Protocol Command Decode",
            "severity":3
        },
        "direction":"to_server",
        "flow":{
            "pkts_toserver":5,"pkts_toclient":2,"bytes_toserver":1858,"bytes_toclient":132,"start":"2017-07-07T09:00:35.000000+0000",
            "src_ip":"192.168.10.9","dest_ip":"192.168.10.3","src_port":1033,"dest_port":88
        }
    }

    
    alert = await parser.parse_line(line_data)
    
    assert isinstance(alert, Alert)
    assert alert.message == "SURICATA TCPv4 invalid checksum"
    assert alert.severity == 0.33


@pytest.mark.asyncio
async def test_parse_line_missing_fields(parser: SuricataParser):
    # Missing dest_ip and dest_port
    line_data = {
        "timestamp": "2025-02-01T12:00:00Z",
        "src_ip": "192.168.1.1",
        "src_port": 80,
        "event_type": "alert",
        "alert": {"signature": "Test Attack", "severity": 1}
    }  
    
    alert = await parser.parse_line(line_data)
    
    assert alert is None, "Expected None due to missing fields"


@pytest.mark.asyncio
async def test_normalize_threat_levels(parser: SuricataParser):   
    assert await parser.normalize_threat_levels(1) == 1.0
    assert await parser.normalize_threat_levels(2) == 0.66
    assert await parser.normalize_threat_levels(3) == 0.33
    assert await parser.normalize_threat_levels(4) is None
    assert await parser.normalize_threat_levels(None) is None
    
    
@pytest.mark.asyncio
async def test_parse_line_unsupported_event_type(parser: SuricataParser):
    # Missing dest_ip and dest_port
    line_data = {
        "timestamp":"2017-07-07T09:00:35.000000+0000",
        "flow_id":844425276156800,
        "pcap_cnt":347,
        "event_type":"unsupported",
        "src_ip":"192.168.10.9",
        "src_port":1033,
        "dest_ip":"192.168.10.3",
        "dest_port":88,
        "proto":"TCP",
        "pkt_src":"wire/pcap",
        "alert":{
            "action":"allowed",
            "gid":1,
            "signature_id":2200074,
            "rev":2,
            "signature":"SURICATA TCPv4 invalid checksum",
            "category":"Generic Protocol Command Decode",
            "severity":3
        },
        "direction":"to_server",
        "flow":{
            "pkts_toserver":5,"pkts_toclient":2,"bytes_toserver":1858,"bytes_toclient":132,"start":"2017-07-07T09:00:35.000000+0000",
            "src_ip":"192.168.10.9","dest_ip":"192.168.10.3","src_port":1033,"dest_port":88
        }
    }

    
    alert = await parser.parse_line(line_data)
    
    assert alert is None, "Expected None due to missing fields"