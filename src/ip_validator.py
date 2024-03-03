from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
import socket
import ipaddress

app = FastAPI()

# Definir modelo para la base de datos
Base = declarative_base()

class IPAddress(Base):
    __tablename__ = "ip_addresses"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True, unique=True)
    is_public = Column(Boolean)
    nslookup_result = Column(String)

# Configurar la base de datos
DATABASE_URL = "sqlite:///./test.sqlite"
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(bind=engine)

# Configurar la sesión de la base de datos
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Modelo Pydantic para la entrada del API
class IPAddressInput(BaseModel):
    ip: str

@app.get("/get_ip_info/{ip_address}")
async def get_ip_info(ip_address: str):
    # Consultar la base de datos para obtener información de la IP
    db = SessionLocal()
    db_ip = db.query(IPAddress).filter(IPAddress.ip_address == ip_address).first()
    db.close()

    # Verificar si la IP existe en la base de datos
    if db_ip is None:
        raise HTTPException(status_code=404, detail="Dirección IP no encontrada")

    # Construir y retornar el JSON con la información de la IP
    return {
        "ip_address": db_ip.ip_address,
        "is_public": db_ip.is_public,
        "nslookup_result": db_ip.nslookup_result
    }

# Ruta principal del API
@app.post("/check_ip/")
async def check_ip_address(ip_input: IPAddressInput):
    ip_address = ip_input.ip

    # Validar si la dirección IP es válida
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        raise HTTPException(status_code=400, detail="Dirección IP no válida")

    # Determinar si es una IP pública o privada
    is_public = not ip_address.startswith(('192.', '10.', '172.16.'))

    # Realizar nslookup
    try:
        nslookup_result = socket.gethostbyaddr(ip_address)
    except socket.herror as e:
        nslookup_result = str(e)

    nslookup_result_str = str(nslookup_result)

    # Guardar en la base de datos
    db = SessionLocal()
    db_ip = IPAddress(ip_address=ip_address, is_public=is_public, nslookup_result=nslookup_result_str)
    db.add(db_ip)
    db.commit()
    db.refresh(db_ip)

    # Responder con la información en formato JSON
    return {
        "ip_address": db_ip.ip_address,
        "is_public": db_ip.is_public,
        "nslookup_result": db_ip.nslookup_result
    }
