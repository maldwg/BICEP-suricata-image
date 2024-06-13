from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.utils.fastapi import routes
import os
import importlib
from .utils.models.ids_base import IDSBase


app = FastAPI()

origins = [
    "*"
]


@app.on_event("startup")
async def startup_event():
    module_name = os.getenv("IDS_MODULE")
    class_name = os.getenv("IDS_CLASS")

    if not module_name or not class_name:
        raise ValueError("IDS_MODULE or IDS_CLASS environment variable not set")

    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)

    if not issubclass(cls, IDSBase):
        raise TypeError(f"{class_name} is not a subclass of IDSBase")

    app.state.ids_instance = cls()


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes.router)