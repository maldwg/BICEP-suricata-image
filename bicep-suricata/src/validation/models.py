from pydantic import BaseModel

class NetworkAnalysisData(BaseModel):
    """

    """
    container_id: int


class StaticAnalysisData(BaseModel):
    """

    """
    container_id: int
    dataset_id: int