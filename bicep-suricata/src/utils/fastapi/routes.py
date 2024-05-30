from fastapi import APIRouter, Depends
from ..models.ids_base import IDSBase
import importlib
import sys
import os
router = APIRouter()

def get_ids_instance() -> IDSBase:
    """
    Method to get the desired Clas of type IDSBase for each container setup.
    This method is injected into the endpoints necessary and exploits the polymorphism of the implementations to execute the functionalities
    """
    module_name = os.getenv("IDS_MODULE")
    class_name = os.getenv("IDS_CLASS")

    if not module_name or not class_name:
        raise ValueError("IDS_MODULE or IDS_CLASS environment variable not set")

    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)

    if not issubclass(cls, IDSBase):
        raise TypeError(f"{class_name} is not a subclass of IDSBase")

    return cls()

@router.get("/")
async def test(ids: IDSBase = Depends(get_ids_instance)):
    return {"message": ids.configure()}