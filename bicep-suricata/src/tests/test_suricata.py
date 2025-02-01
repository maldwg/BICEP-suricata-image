import pytest
import shutil
import json
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import Response
from src.models.suricata import Suricata
import tempfile
import ruamel.yaml
from pathlib import Path


@pytest.fixture
def ids():
    ids = Suricata()
    ids.container_id = 123
    ids.tap_interface_name = "tap123"
    ids.configuration_location = "my/config/location"
    ids.ruleset_location = "my/ruleset/location"
    ids.log_location = "my/log/location"
    return ids

@pytest.mark.asyncio
@patch("shutil.move")
@patch("os.mkdir")
@patch("src.models.suricata.Suricata.enhance_suricata_config_to_allow_for_ensemble")
async def test_configure(enhance_config_mock, mock_mkdir, mock_shutil, ids: Suricata):
    mock_mkdir.return_value = None
    response = await ids.configure("/path/to/config.yaml")
    mock_shutil.assert_called_once_with("/path/to/config.yaml", ids.configuration_location)
    mock_mkdir.assert_called_once_with(ids.log_location)
    assert response == "succesfully configured"


@pytest.mark.asyncio
@patch("shutil.move")
async def test_configure_ruleset(mock_shutil):
    suricata = Suricata()
    response = await suricata.configure_ruleset("/path/to/rules.rules")
    assert response == "succesfuly setup ruleset"


@pytest.mark.asyncio
@patch("src.models.suricata.execute_command", new_callable=AsyncMock)
async def test_execute_network_analysis_command(mock_execute_command, ids: Suricata):
    """Test execute_network_analysis_command calls execute_command correctly."""
    mock_execute_command.return_value = 555  
    pid = await ids.execute_network_analysis_command()
    mock_execute_command.assert_called_once_with([
        "suricata", "-c", ids.configuration_location, "-i", "tap123", "-S", ids.ruleset_location, "-l", ids.log_location
    ])
    assert pid == 555



@pytest.mark.asyncio
@patch("src.models.suricata.execute_command", new_callable=AsyncMock)
async def test_execute_static_analysis_command(mock_execute_command, ids: Suricata):
    mock_execute_command.return_value = 777  
    dataset_path = "/path/to/capture.pcap"
    pid = await ids.execute_static_analysis_command(dataset_path)
    mock_execute_command.assert_called_once_with([
        "suricata", "-c", ids.configuration_location, "-S", ids.ruleset_location,  "-r", dataset_path, "-l", ids.log_location
    ])
    assert pid == 777


# TODO finish testing  parser
# TODO derive template tests 
# TODO add temoplate tests in slips
# TODO cahnge slips according to suricata bcs we made some changes to utils
@pytest.mark.asyncio
async def test_enhance_suricata_config_to_allow_for_ensemble(ids: Suricata):
    temp_dir = tempfile.mkdtemp()
    temp_config_path = Path(temp_dir) / "suricata_temp.yaml"
    shutil.copy("bicep-suricata/src/tests/testfiles/suricata.yaml", temp_config_path)
    ids.configuration_location = str(temp_config_path)

    await ids.enhance_suricata_config_to_allow_for_ensemble()

    yaml = ruamel.yaml.YAML()
    with open(temp_config_path, "r") as modified_yaml:
        modified_config = yaml.load(modified_yaml)

    assert "af-packet" in modified_config
    assert any(
        entry.get("interface") == ids.tap_interface_name and 
        entry.get("cluster-id") == ids.container_id
        for entry in modified_config["af-packet"]
    ), "New tap interface entry was not added to 'af-packet'"

    shutil.rmtree(temp_dir)