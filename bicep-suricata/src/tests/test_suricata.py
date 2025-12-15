import pytest
import shutil
import json
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock, mock_open
from httpx import Response
from fastapi import HTTPException
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
@patch("os.makedirs")
@patch(
    "src.models.suricata.Suricata.enhance_suricata_config_to_allow_for_ensemble",
    new_callable=AsyncMock,
)
async def test_configure(
    mock_enhance_config, mock_makedirs, mock_shutil, ids: Suricata
):
    """Test successful configuration with all steps."""
    mock_makedirs.return_value = None
    mock_enhance_config.return_value = None

    response = await ids.configure("/path/to/config.yaml")

    # Verify all steps were called correctly
    mock_shutil.assert_called_once_with(
        "/path/to/config.yaml", ids.configuration_location
    )
    mock_makedirs.assert_called_once_with(ids.log_location, exist_ok=True)
    mock_enhance_config.assert_called_once()
    assert response == "succesfully configured"


@pytest.mark.asyncio
@patch("shutil.move")
@patch("os.makedirs")
@patch(
    "src.models.suricata.Suricata.enhance_suricata_config_to_allow_for_ensemble",
    new_callable=AsyncMock,
)
async def test_configure_with_existing_log_directory(
    mock_enhance_config, mock_makedirs, mock_shutil, ids: Suricata
):
    """Test configuration when log directory already exists (exist_ok=True should handle this)."""
    mock_makedirs.return_value = None  # makedirs with exist_ok=True doesn't raise error
    mock_enhance_config.return_value = None

    response = await ids.configure("/path/to/config.yaml")

    assert response == "succesfully configured"
    mock_makedirs.assert_called_once_with(ids.log_location, exist_ok=True)


@pytest.mark.asyncio
@patch("shutil.move")
@patch("os.makedirs")
@patch(
    "src.models.suricata.Suricata.enhance_suricata_config_to_allow_for_ensemble",
    new_callable=AsyncMock,
)
async def test_configure_makedirs_failure(
    mock_enhance_config, mock_makedirs, mock_shutil, ids: Suricata
):
    """Test configuration fails gracefully when directory creation fails."""
    mock_makedirs.side_effect = PermissionError("Permission denied")

    with pytest.raises(HTTPException) as exc_info:
        await ids.configure("/path/to/config.yaml")

    assert exc_info.value.status_code == 500
    assert "Exception occured" in exc_info.value.detail
    # shutil.move should have been called before makedirs failed
    mock_shutil.assert_called_once()
    # enhance_config should not be called if makedirs failed
    mock_enhance_config.assert_not_called()


@pytest.mark.asyncio
@patch("shutil.move")
@patch("os.makedirs")
@patch(
    "src.models.suricata.Suricata.enhance_suricata_config_to_allow_for_ensemble",
    new_callable=AsyncMock,
)
async def test_configure_enhance_config_failure(
    mock_enhance_config, mock_makedirs, mock_shutil, ids: Suricata
):
    """Test configuration fails when enhance_suricata_config fails."""
    mock_makedirs.return_value = None
    mock_enhance_config.side_effect = Exception("Failed to enhance config")

    with pytest.raises(HTTPException) as exc_info:
        await ids.configure("/path/to/config.yaml")

    assert exc_info.value.status_code == 500
    assert "Exception occured" in exc_info.value.detail
    mock_shutil.assert_called_once()
    mock_makedirs.assert_called_once()
    mock_enhance_config.assert_called_once()


@pytest.mark.asyncio
@patch("shutil.move")
@patch("os.makedirs")
@patch(
    "src.models.suricata.Suricata.enhance_suricata_config_to_allow_for_ensemble",
    new_callable=AsyncMock,
)
async def test_configure_shutil_move_failure(
    mock_enhance_config, mock_makedirs, mock_shutil, ids: Suricata
):
    """Test configuration fails when file move fails."""
    mock_shutil.side_effect = FileNotFoundError("Source file not found")

    # Since shutil.move is outside the try-except, it will raise directly
    with pytest.raises(FileNotFoundError):
        await ids.configure("/path/to/config.yaml")

    mock_shutil.assert_called_once()
    # Subsequent steps should not be called
    mock_makedirs.assert_not_called()
    mock_enhance_config.assert_not_called()


@pytest.mark.asyncio
@patch("shutil.move")
async def test_configure_ruleset(mock_shutil):
    """Test ruleset configuration."""
    suricata = Suricata()
    response = await suricata.configure_ruleset("/path/to/rules.rules")
    assert response == "succesfuly setup ruleset"
    mock_shutil.assert_called_once_with(
        "/path/to/rules.rules", suricata.ruleset_location
    )


@pytest.mark.asyncio
@patch("shutil.move")
async def test_configure_ruleset_failure(mock_shutil):
    """Test ruleset configuration fails when file move fails."""
    suricata = Suricata()
    mock_shutil.side_effect = IOError("Failed to move file")

    with pytest.raises(IOError):
        await suricata.configure_ruleset("/path/to/rules.rules")


@pytest.mark.asyncio
@patch("src.models.suricata.execute_command_async", new_callable=AsyncMock)
async def test_execute_network_analysis_command(mock_execute_command, ids: Suricata):
    """Test execute_network_analysis_command calls execute_command correctly."""
    mock_execute_command.return_value = 555
    pid = await ids.execute_network_analysis_command()
    mock_execute_command.assert_called_once_with(
        [
            "suricata",
            "-c",
            ids.configuration_location,
            "-i",
            "tap123",
            "-S",
            ids.ruleset_location,
            "-l",
            ids.log_location,
        ]
    )
    assert pid == 555


@pytest.mark.asyncio
@patch("src.models.suricata.execute_command_async", new_callable=AsyncMock)
async def test_execute_static_analysis_command(mock_execute_command, ids: Suricata):
    """Test static analysis command execution."""
    mock_execute_command.return_value = 777
    dataset_path = "/path/to/capture.pcap"
    pid = await ids.execute_static_analysis_command(dataset_path)
    mock_execute_command.assert_called_once_with(
        [
            "suricata",
            "-c",
            ids.configuration_location,
            "-S",
            ids.ruleset_location,
            "-r",
            dataset_path,
            "-l",
            ids.log_location,
        ]
    )
    assert pid == 777


@pytest.mark.asyncio
async def test_enhance_suricata_config_to_allow_for_ensemble(ids: Suricata):
    """Test enhance config adds tap interface entry to af-packet section."""
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
        entry.get("interface") == ids.tap_interface_name
        and entry.get("cluster-id") == ids.container_id
        for entry in modified_config["af-packet"]
    ), "New tap interface entry was not added to 'af-packet'"

    shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_enhance_suricata_config_missing_af_packet_key(ids: Suricata):
    """Test enhance config fails gracefully if af-packet key is missing from config."""
    temp_dir = tempfile.mkdtemp()
    temp_config_path = Path(temp_dir) / "suricata_invalid.yaml"

    # Create a minimal YAML without af-packet section
    yaml = ruamel.yaml.YAML()
    minimal_config = {"logging": {"default-log-level": "info"}}
    with open(temp_config_path, "w") as f:
        yaml.dump(minimal_config, f)

    ids.configuration_location = str(temp_config_path)

    # This should raise KeyError or similar since af-packet key doesn't exist
    with pytest.raises(Exception):  # Could be KeyError, TypeError, etc.
        await ids.enhance_suricata_config_to_allow_for_ensemble()

    shutil.rmtree(temp_dir)
