import os
import logging
import random
import string
import shutil
import psycopg2
import psycopg2.extras
import bcrypt
import re
import stripe
from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.staticfiles import StaticFiles 
from contextlib import asynccontextmanager
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import date, datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

# ==========================================
# 1. CONFIGURACIÓN
# ==========================================
log = logging.getLogger("uvicorn")
POSTGRES_URL = os.environ.get("POSTGRES_URL")
db_connections = {}

# Stripe keys
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

# Google API Key (para Gemini)
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")

# URL del frontend (usada en las back_urls / success/cancel)
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:8080")

# Verificación de Seguridad pa  ra Stripe
if not STRIPE_SECRET_KEY:
    print("\n  ADVERTENCIA: No se encontró STRIPE_SECRET_KEY en las variables de entorno.")
    print("  La API arrancará, pero los pagos con Stripe fallarán.\n")
    stripe = None
else:
    try:
        stripe.api_key = STRIPE_SECRET_KEY
        print(" Stripe configurado correctamente.")
    except Exception as e:
        print(f" Error al iniciar Stripe: {e}")
        stripe = None


UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# ==========================================
# 2. MODELOS DE DATOS (Pydantic)
# ==========================================

# --- AUTH & REGISTRO ---
class RegistroCliente(BaseModel):
    nombre: str
    apellidos: str
    correo_electronico: EmailStr
    password: str
    telefono: str
    fecha_nacimiento: date
    calle: str
    colonia: str
    numero_exterior: str
    numero_interior: Optional[str] = None
    codigo_postal: str
    ciudad: str
    referencias: Optional[str] = None
    latitud: Optional[float] = None
    longitud: Optional[float] = None

    # Modelo de datos que recibimos del frontend
class SolicitudPago(BaseModel):
    servicio_id: str
    titulo: str
    precio: float
    trabajador_id: str
    propuesta_id: str

class RegistroTrabajador(BaseModel):
    nombre: str
    apellidos: str
    correo_electronico: EmailStr
    password: str
    telefono: str
    fecha_nacimiento: date
    descripcion_bio: str
    anios_experiencia: int
    tarifa_hora: float
    oficios_ids: List[int]
    latitud: Optional[float] = None
    longitud: Optional[float] = None

class DatosVerificacion(BaseModel):
    correo: EmailStr
    codigo: str

class LoginRequest(BaseModel):
    correo: EmailStr
    password: str

# --- PERFILES ---
# --- MODELO LIMPIO (Sin dirección) ---
class PerfilTrabajadorUpdate(BaseModel):
    nombre: str
    apellidos: str
    telefono: str
    # Datos Profesionales
    descripcion_bio: str
    anios_experiencia: int
    tarifa_hora: float
    # Docs y Fotos
    foto_perfil_url: Optional[str] = None
    foto_ine_frente_url: Optional[str] = None
    foto_ine_reverso_url: Optional[str] = None
    antecedentes_penales_url: Optional[str] = None

class PerfilClienteUpdate(BaseModel):
    nombre: str
    apellidos: str
    telefono: str
    correo_electronico: EmailStr
    calle: str
    colonia: str
    codigo_postal: str
    ciudad: str
    numero_exterior: str
    numero_interior: Optional[str] = None
    referencias: Optional[str] = None
    latitud: Optional[float] = None
    longitud: Optional[float] = None
    foto_perfil_url: Optional[str] = None
    password_nuevo: Optional[str] = None

# --- SERVICIOS Y PROPUESTAS ---
class CrearServicio(BaseModel):
    cliente_id: str
    categoria_id: int
    titulo: str
    descripcion: str
    fecha_programada: Optional[datetime] = None
    precio_estimado: Optional[float] = None
    direccion_texto: str
    latitud: float
    longitud: float
    foto_evidencia_url: Optional[str] = None

class CrearPropuesta(BaseModel):
    servicio_id: str
    trabajador_id: str
    precio_oferta: float
    mensaje: str

class AceptarPropuesta(BaseModel):
    servicio_id: str
    trabajador_id: str
    propuesta_id: str

class CalificarServicio(BaseModel):
    calificacion: int # 1 a 5
    resena: Optional[str] = ""

# --- ADMIN ---
class AccionAdmin(BaseModel):
    usuario_id: str
    accion: str
    dias_bloqueo: Optional[int] = 0

# ==========================================
# 3. HELPERS
# ==========================================
def encriptar_password(password_plana: str) -> str:
    password_bytes = password_plana[:72].encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def generar_codigo_verificacion():
    return ''.join(random.choices(string.digits, k=6))

def verificar_password(password_plana: str, password_hash: str) -> bool:
    password_bytes = password_plana[:72].encode('utf-8')
    hash_bytes = password_hash.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hash_bytes)

# ==========================================
# 4. LIFESPAN & APP
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("🚀 Iniciando API...")
    try:
        pg_conn = psycopg2.connect(POSTGRES_URL, cursor_factory=psycopg2.extras.DictCursor)
        db_connections["pg_conn"] = pg_conn
        
        # Admin por defecto
        with pg_conn.cursor() as cur:
            pass_admin = encriptar_password("admin123")
            cur.execute("""
                INSERT INTO usuarios (nombre, apellidos, correo_electronico, password_hash, telefono, es_admin, activo, fecha_nacimiento)
                VALUES ('Super', 'Admin', 'admin@sistema.com', %s, '000', TRUE, TRUE, '2000-01-01')
                ON CONFLICT (correo_electronico) DO NOTHING
            """, (pass_admin,))
            pg_conn.commit()
        log.info("✅ Postgres Conectado.")
    except Exception as e:
        if 'pg_conn' in locals() and pg_conn: pg_conn.rollback()
        log.error(f"❌ Error al iniciar Postgres: {e}")
    yield
    if db_connections.get("pg_conn"):
        db_connections["pg_conn"].close()

app = FastAPI(lifespan=lifespan)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Montar la carpeta frontend para servir archivos HTML/CSS/JS
FRONTEND_DIR = "frontend"
if os.path.exists(FRONTEND_DIR):
    app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")
    log.info(f"✅ Carpeta frontend montada en /frontend")
else:
    log.warning(f"⚠️ Carpeta frontend no encontrada en {FRONTEND_DIR}")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ==========================================
# 5. ENDPOINTS: GENERAL & AUTH
# ==========================================

@app.get("/config")
def get_config():
    """Endpoint que retorna la configuración disponible para el frontend"""
    return {
        "GOOGLE_API_KEY": GOOGLE_API_KEY or "",
        "STRIPE_PUBLISHABLE_KEY": STRIPE_PUBLISHABLE_KEY or "",
        "FRONTEND_URL": FRONTEND_URL
    }

@app.get("/")
def read_root(): return {"mensaje": "API ISF Funcionando"}


# --- UPLOAD CORREGIDO (Sanitizar Nombres) ---
@app.post("/upload")
async def subir_imagen(file: UploadFile = File(...)):
    try:
        # 1. Limpiar nombre: reemplazar espacios y caracteres raros por guion bajo
        nombre_limpio = re.sub(r'[^a-zA-Z0-9_.-]', '_', file.filename)
        
        # 2. Crear nombre único
        nombre_archivo = f"{generar_codigo_verificacion()}_{nombre_limpio}"
        
        # 3. Guardar
        ruta_guardado = os.path.join(UPLOAD_DIR, nombre_archivo)
        with open(ruta_guardado, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # 4. Devolver URL válida
        url_publica = f"https://servicios-1-0.onrender.com/uploads/{nombre_archivo}"
        return {"url": url_publica}
        
    except Exception as e:
        log.error(f"Error subiendo: {e}")
        raise HTTPException(500, "Error subiendo imagen")
    
    

@app.get("/categorias")
def obtener_categorias():
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, nombre, icono_url FROM categorias_oficios")
            return [dict(cat) for cat in cursor.fetchall()]
    except Exception: raise HTTPException(500, "Error")

@app.post("/registro-cliente")
def registrar_cliente(datos: RegistroCliente):
    conn = db_connections.get("pg_conn")
    if conn is None: raise HTTPException(503, "Sin BD")
    try:
        with conn.cursor() as cursor:
            hashed_pass = encriptar_password(datos.password)
            codigo = generar_codigo_verificacion()
            cursor.execute("INSERT INTO usuarios (nombre, apellidos, correo_electronico, password_hash, telefono, fecha_nacimiento, activo, codigo_verificacion) VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s) RETURNING id", (datos.nombre, datos.apellidos, datos.correo_electronico, hashed_pass, datos.telefono, datos.fecha_nacimiento, codigo))
            nuevo_id = cursor.fetchone()['id']
            cursor.execute("INSERT INTO detalles_cliente (usuario_id, calle, colonia, numero_exterior, numero_interior, codigo_postal, ciudad, referencias_domicilio, latitud, longitud) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (nuevo_id, datos.calle, datos.colonia, datos.numero_exterior, datos.numero_interior, datos.codigo_postal, datos.ciudad, datos.referencias, datos.latitud, datos.longitud))
            conn.commit()
            print(f"\n===  CLIENTE: {datos.correo_electronico} | : {codigo} ===\n")
            return {"mensaje": "Cliente registrado.", "correo": datos.correo_electronico}
    except psycopg2.IntegrityError: conn.rollback(); raise HTTPException(400, "Correo ya registrado.")
    except Exception as e: conn.rollback(); log.error(e); raise HTTPException(500, f"Error: {str(e)}")

@app.post("/registro-trabajador")
def registrar_trabajador(datos: RegistroTrabajador):
    conn = db_connections.get("pg_conn")
    if conn is None: raise HTTPException(503, "Sin BD")
    try:
        with conn.cursor() as cursor:
            hashed_pass = encriptar_password(datos.password)
            codigo = generar_codigo_verificacion()
            cursor.execute("INSERT INTO usuarios (nombre, apellidos, correo_electronico, password_hash, telefono, fecha_nacimiento, activo, codigo_verificacion) VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s) RETURNING id", (datos.nombre, datos.apellidos, datos.correo_electronico, hashed_pass, datos.telefono, datos.fecha_nacimiento, codigo))
            nuevo_id = cursor.fetchone()['id']
            cursor.execute("INSERT INTO detalles_trabajador (usuario_id, descripcion_bio, anios_experiencia, tarifa_hora_estimada, latitud, longitud) VALUES (%s, %s, %s, %s, %s, %s)", (nuevo_id, datos.descripcion_bio, datos.anios_experiencia, datos.tarifa_hora, datos.latitud, datos.longitud))
            if datos.oficios_ids:
                for oficio_id in datos.oficios_ids:
                    cursor.execute("INSERT INTO trabajador_oficios (usuario_id, categoria_id) VALUES (%s, %s)", (nuevo_id, oficio_id))
            conn.commit()
            print(f"\n===  TRABAJADOR: {datos.correo_electronico} | : {codigo} ===\n")
            return {"mensaje": "Trabajador registrado.", "correo": datos.correo_electronico}
    except psycopg2.IntegrityError: conn.rollback(); raise HTTPException(400, "Correo ya registrado.")
    except Exception as e: conn.rollback(); log.error(e); raise HTTPException(500, f"Error interno")

# ... (El inicio del archivo sigue igual) ...

# --- ENDPOINT PAGO CORREGIDO ---
@app.post("/pagos/crear-preferencia") # Mantener la ruta para compatibilidad con el frontend
def crear_preferencia_pago(datos: SolicitudPago):
    # Usamos Stripe Checkout: creamos una sesión y devolvemos la URL de redirección
    if stripe is None:
        # Usamos 503 para indicar servicio no disponible y proporcionar más contexto
        raise HTTPException(503, "Stripe no configurado. Verifica STRIPE_SECRET_KEY en las variables de entorno.")

    # Validar que los IDs existan en BD
    conn = db_connections.get("pg_conn")
    if conn is None:
        raise HTTPException(503, "Base de datos no disponible.")
    
    try:
        with conn.cursor() as cursor:
            # Verificar que el servicio existe
            cursor.execute("SELECT id FROM servicios WHERE id = %s", (datos.servicio_id,))
            if not cursor.fetchone():
                raise HTTPException(404, "Servicio no encontrado.")
            
            # Verificar que la propuesta existe
            cursor.execute("SELECT id FROM propuestas WHERE id = %s", (datos.propuesta_id,))
            if not cursor.fetchone():
                raise HTTPException(404, "Propuesta no encontrada.")
            
            # Verificar que el trabajador existe
            cursor.execute("SELECT id FROM usuarios WHERE id = %s", (datos.trabajador_id,))
            if not cursor.fetchone():
                raise HTTPException(404, "Trabajador no encontrado.")
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error validando datos de pago: {e}")
        raise HTTPException(500, "Error validando información de pago.")

    try:
        # Crear sesión de Checkout
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'mxn',
                    'unit_amount': int(round(float(datos.precio) * 100)),
                    'product_data': { 'name': datos.titulo }
                },
                'quantity': 1
            }],
            mode='payment',
            success_url=f"{FRONTEND_URL}/frontend/dashboard.html?status=approved&session={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{FRONTEND_URL}/frontend/dashboard.html?status=failure",
            metadata={
                'servicio_id': datos.servicio_id,
                'propuesta_id': datos.propuesta_id,
                'trabajador_id': datos.trabajador_id
            },
            # Estos parámetros aseguran que Stripe redirija correctamente después del pago
            automatic_tax={'enabled': False},
        )

        log.info(f"✅ Sesión de Stripe creada: {session.id}")
        return {
            "session_id": session.id, 
            "init_point": session.url,
            "mensaje": "Redirígete a Stripe para completar el pago"
        }

    except Exception as e:
        # Logueamos el error y devolvemos un mensaje con detalle para el frontend
        log.error(f"Error procesando pago con Stripe: {e}")
        raise HTTPException(500, f"Error procesando el pago con Stripe: {str(e)}")


# --- ENDPOINT DE DIAGNÓSTICO DE STRIPE ---
@app.get("/stripe/status")
def stripe_status():
    """Devuelve información básica sobre la configuración de Stripe y prueba conectividad."""
    if stripe is None:
        raise HTTPException(503, "Stripe no configurado. Verifica STRIPE_SECRET_KEY en las variables de entorno.")

    try:
        # Hacemos una consulta de lectura no destructiva para comprobar conectividad
        acct = stripe.Account.retrieve()
        info = {
            "configured": True,
            "account_id": acct.get("id"),
            "display_name": acct.get("display_name") or acct.get("email"),
            "message": "Conexión con Stripe OK." 
        }
        return info
    except Exception as e:
        print(f"Error probando conexión a Stripe: {e}")
        raise HTTPException(500, f"Error conectando con Stripe: {str(e)}")


# --- ENDPOINT PARA VALIDAR EL ESTADO DEL PAGO DESPUÉS DEL RETORNO ---
@app.get("/pagos/validar-sesion/{session_id}")
def validar_sesion_pago(session_id: str):
    """
    Valida si una sesión de Stripe fue pagada correctamente.
    Si el pago está completado, actualiza automáticamente la BD:
    - Asigna el trabajador al servicio
    - Actualiza el estado del servicio a EN_PROCESO
    - Marca la propuesta como aceptada
    - Guarda el precio pagado
    """
    log.info(f"🔍 Validando sesión de Stripe: {session_id}")
    
    if stripe is None:
        log.error("❌ Stripe no está configurado")
        raise HTTPException(503, "Stripe no configurado.")
    
    conn = db_connections.get("pg_conn")
    if conn is None:
        log.error("❌ Base de datos no disponible")
        raise HTTPException(503, "Base de datos no disponible")
    
    try:
        # 1. Obtener información de la sesión de Stripe
        session = stripe.checkout.Session.retrieve(session_id)
        log.info(f"📊 Estado de pago: {session.payment_status}")
        log.info(f"📦 Metadata: {session.metadata}")
        
        if session.payment_status == "paid":
            # El pago fue completado ✅
            log.info(f"✅ Pago completado: {session_id}")
            
            # 2. Extraer metadata de la sesión
            metadata = session.metadata if session.metadata else {}
            servicio_id = metadata.get('servicio_id')
            propuesta_id = metadata.get('propuesta_id')
            trabajador_id = metadata.get('trabajador_id')
            precio_pagado = (session.amount_total / 100) if session.amount_total else 0
            
            log.info(f"📋 Datos de pago:")
            log.info(f"   Servicio: {servicio_id}")
            log.info(f"   Trabajador: {trabajador_id}")
            log.info(f"   Propuesta: {propuesta_id}")
            log.info(f"   Monto: ${precio_pagado}")
            
            # 3. Actualizar BD si tenemos los datos necesarios
            resultado_actualizacion = {
                "actualizado": False,
                "razon": "Datos incompletos en metadata"
            }
            
            if servicio_id and propuesta_id and trabajador_id:
                try:
                    with conn.cursor() as cursor:
                        # Verificar estado actual del servicio
                        cursor.execute(
                            "SELECT estado, trabajador_id FROM servicios WHERE id = %s",
                            (servicio_id,)
                        )
                        resultado = cursor.fetchone()
                        
                        if not resultado:
                            resultado_actualizacion = {
                                "actualizado": False,
                                "razon": "Servicio no encontrado"
                            }
                            log.warning(f"⚠️ Servicio {servicio_id} no existe")
                        
                        elif resultado['estado'] in ['EN_PROCESO', 'TERMINADO']:
                            # Ya fue procesado
                            resultado_actualizacion = {
                                "actualizado": False,
                                "razon": f"Servicio ya en estado {resultado['estado']}"
                            }
                            log.info(f"ℹ️ Servicio {servicio_id} ya estaba actualizado")
                        
                        else:
                            # Actualizar estado a EN_PROCESO
                            cursor.execute("""
                                UPDATE servicios 
                                SET trabajador_id = %s, 
                                    estado = 'EN_PROCESO', 
                                    precio_estimado = %s
                                WHERE id = %s AND estado != 'EN_PROCESO' AND estado != 'TERMINADO'
                                RETURNING id
                            """, (trabajador_id, precio_pagado, servicio_id))
                            
                            update_result = cursor.fetchone()
                            
                            if update_result:
                                # Marcar propuesta como aceptada
                                cursor.execute("""
                                    UPDATE propuestas 
                                    SET aceptada = TRUE
                                    WHERE id = %s
                                    RETURNING id
                                """, (propuesta_id,))
                                
                                prop_result = cursor.fetchone()
                                
                                if prop_result:
                                    conn.commit()
                                    resultado_actualizacion = {
                                        "actualizado": True,
                                        "razon": "Servicio asignado y propuesta aceptada exitosamente"
                                    }
                                    log.info(f"✅ BD actualizada correctamente:")
                                    log.info(f"   - Servicio {servicio_id} → EN_PROCESO")
                                    log.info(f"   - Trabajador asignado: {trabajador_id}")
                                    log.info(f"   - Propuesta {propuesta_id} → ACEPTADA")
                                    log.info(f"   - Precio guardado: ${precio_pagado}")
                                else:
                                    conn.rollback()
                                    resultado_actualizacion = {
                                        "actualizado": False,
                                        "razon": "Error actualizando propuesta"
                                    }
                                    log.error(f"❌ No se pudo actualizar propuesta {propuesta_id}")
                            else:
                                conn.rollback()
                                resultado_actualizacion = {
                                    "actualizado": False,
                                    "razon": "Error actualizando servicio"
                                }
                                log.error(f"❌ No se pudo actualizar servicio {servicio_id}")
                
                except Exception as e:
                    conn.rollback()
                    resultado_actualizacion = {
                        "actualizado": False,
                        "razon": f"Error de BD: {str(e)}"
                    }
                    log.error(f"❌ Error en transacción BD: {e}")
            
            # 4. Devolver respuesta
            return {
                "status": "approved",
                "session_id": session.id,
                "amount_total": precio_pagado,
                "message": "Pago completado exitosamente",
                "database_update": resultado_actualizacion,
                "metadata": {
                    "servicio_id": servicio_id,
                    "trabajador_id": trabajador_id,
                    "propuesta_id": propuesta_id
                }
            }
        
        elif session.payment_status == "unpaid":
            # El pago sigue pendiente ⏳
            log.warning(f"⏳ Pago pendiente: {session_id}")
            return {
                "status": "pending",
                "session_id": session.id,
                "message": "El pago aún está pendiente. Por favor intenta nuevamente.",
                "next_action": "Espera o intenta nuevamente"
            }
        
        else:
            # Estado desconocido o cancelado ❌
            log.warning(f"❌ Estado desconocido: {session.payment_status}")
            return {
                "status": "unknown",
                "session_id": session.id,
                "payment_status": session.payment_status,
                "message": "No se pudo determinar el estado del pago"
            }
    
    except Exception as e:
        log.error(f"Error validando sesión Stripe: {e}")
        raise HTTPException(500, f"Error validando sesión de pago: {str(e)}")

# ... (El resto del archivo sigue igual) ...
    
@app.post("/verificar-cuenta")
def verificar_cuenta(datos: DatosVerificacion):
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, codigo_verificacion, activo FROM usuarios WHERE correo_electronico = %s", (datos.correo,))
            u = cursor.fetchone()
            if not u: raise HTTPException(404, "Usuario no encontrado.")
            if u['activo']: return {"mensaje": "Cuenta ya activa."}
            if u['codigo_verificacion'] == datos.codigo:
                cursor.execute("UPDATE usuarios SET activo = TRUE WHERE id = %s", (u['id'],))
                conn.commit()
                return {"mensaje": "¡Cuenta activada!"}
            else: raise HTTPException(400, "Código incorrecto.")
    except Exception as e: conn.rollback(); log.error(e); raise HTTPException(500, "Error interno.")

@app.post("/login")
def login(datos: LoginRequest):
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, nombre, password_hash, activo, es_admin, bloqueado_hasta FROM usuarios WHERE correo_electronico = %s", (datos.correo,))
            u = cursor.fetchone()
            if not u or not u['activo'] or not verificar_password(datos.password, u['password_hash']): 
                raise HTTPException(401, "Credenciales incorrectas o inactiva.")
            
            if u['bloqueado_hasta']:
                bloqueo = u['bloqueado_hasta'].replace(tzinfo=None) if u['bloqueado_hasta'].tzinfo else u['bloqueado_hasta']
                if bloqueo > datetime.now(): raise HTTPException(403, "Cuenta bloqueada.")
            
            es_trabajador = False
            cursor.execute("SELECT 1 FROM detalles_trabajador WHERE usuario_id = %s", (u['id'],))
            if cursor.fetchone(): es_trabajador = True

            return {"mensaje": "Login exitoso", "usuario": {"id": str(u['id']), "nombre": u['nombre'], "es_admin": u['es_admin'], "es_trabajador": es_trabajador}}
    except Exception as e: log.error(e); raise HTTPException(500, "Error interno")

# ==========================================
# 6. ENDPOINTS: PERFILES
# ==========================================


# --- ENDPOINT GET (Sin pedir dirección) ---
@app.get("/mi-perfil/{usuario_id}")
def obtener_perfil_trabajador(usuario_id: str):
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cursor:
            # Solo traemos lo que existe en tu BD
            cursor.execute("""
                SELECT u.nombre, u.apellidos, u.telefono, u.foto_perfil_url,
                       dt.descripcion_bio, dt.anios_experiencia, dt.tarifa_hora_estimada, 
                       dt.calificacion_promedio, dt.total_evaluaciones, dt.validado_por_admin,
                       dt.foto_ine_frente_url, dt.foto_ine_reverso_url, dt.antecedentes_penales_url
                FROM usuarios u
                JOIN detalles_trabajador dt ON u.id = dt.usuario_id
                WHERE u.id = %s
            """, (usuario_id,))
            perfil = cursor.fetchone()
            if not perfil: raise HTTPException(404, "Perfil no encontrado")
            return dict(perfil)
    except Exception as e: log.error(e); raise HTTPException(500, "Error interno")


# --- ENDPOINT PUT (Sin actualizar dirección) ---
@app.put("/mi-perfil/{usuario_id}")
def actualizar_perfil_trabajador(usuario_id: str, datos: PerfilTrabajadorUpdate):
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cursor:
            # 1. Actualizar tabla usuarios (Nombre, Teléfono, Foto Perfil)
            cursor.execute("""
                UPDATE usuarios 
                SET nombre=%s, apellidos=%s, telefono=%s, foto_perfil_url=%s 
                WHERE id=%s
            """, (datos.nombre, datos.apellidos, datos.telefono, datos.foto_perfil_url, usuario_id))
            
            # 2. Actualizar tabla detalles_trabajador (Bio, Experiencia, Tarifa, Docs)
            cursor.execute("""
                UPDATE detalles_trabajador SET 
                descripcion_bio=%s, anios_experiencia=%s, tarifa_hora_estimada=%s,
                foto_ine_frente_url=%s, foto_ine_reverso_url=%s, antecedentes_penales_url=%s
                WHERE usuario_id=%s
            """, (
                datos.descripcion_bio, datos.anios_experiencia, datos.tarifa_hora,
                datos.foto_ine_frente_url, datos.foto_ine_reverso_url, datos.antecedentes_penales_url, 
                usuario_id
            ))
            conn.commit()
            return {"mensaje": "Perfil actualizado correctamente"}
    except Exception as e: 
        conn.rollback()
        log.error(e)
        raise HTTPException(500, "Error al actualizar perfil")
    
@app.get("/mi-perfil-cliente/{usuario_id}")
def get_perfil_cliente(usuario_id: str):
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.nombre, u.apellidos, u.telefono, u.correo_electronico, u.foto_perfil_url, u.fecha_nacimiento,
                       dc.calle, dc.colonia, dc.codigo_postal, dc.ciudad, 
                       dc.numero_exterior, dc.numero_interior, dc.referencias_domicilio,
                       dc.latitud, dc.longitud
                FROM usuarios u
                JOIN detalles_cliente dc ON u.id = dc.usuario_id
                WHERE u.id = %s
            """, (usuario_id,))
            p = cur.fetchone()
            if not p: raise HTTPException(404, "Perfil no encontrado")
            return dict(p)
    except Exception as e: log.error(e); raise HTTPException(500, "Error")

@app.put("/mi-perfil-cliente/{usuario_id}")
def update_perfil_cliente(usuario_id: str, d: PerfilClienteUpdate):
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cur:
            if d.password_nuevo:
                h = encriptar_password(d.password_nuevo)
                cur.execute("UPDATE usuarios SET nombre=%s, apellidos=%s, telefono=%s, correo_electronico=%s, foto_perfil_url=%s, password_hash=%s WHERE id=%s", (d.nombre, d.apellidos, d.telefono, d.correo_electronico, d.foto_perfil_url, h, usuario_id))
            else:
                cur.execute("UPDATE usuarios SET nombre=%s, apellidos=%s, telefono=%s, correo_electronico=%s, foto_perfil_url=%s WHERE id=%s", (d.nombre, d.apellidos, d.telefono, d.correo_electronico, d.foto_perfil_url, usuario_id))

            cur.execute("""
                UPDATE detalles_cliente 
                SET calle=%s, colonia=%s, codigo_postal=%s, ciudad=%s, numero_exterior=%s, numero_interior=%s, referencias_domicilio=%s, latitud=%s, longitud=%s
                WHERE usuario_id=%s
            """, (d.calle, d.colonia, d.codigo_postal, d.ciudad, d.numero_exterior, d.numero_interior, d.referencias, d.latitud, d.longitud, usuario_id))
            conn.commit()
            return {"mensaje": "Perfil actualizado"}
    except Exception as e: conn.rollback(); log.error(e); raise HTTPException(500, "Error update")

# ==========================================
# 7. ENDPOINTS: SERVICIOS Y PROPUESTAS
# ==========================================

@app.post("/servicios")
def crear_servicio(datos: CrearServicio):
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO servicios (cliente_id, categoria_id, titulo, descripcion, fecha_programada, precio_estimado, direccion_texto, latitud, longitud, foto_evidencia_url)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (datos.cliente_id, datos.categoria_id, datos.titulo, datos.descripcion, datos.fecha_programada, datos.precio_estimado, datos.direccion_texto, datos.latitud, datos.longitud, datos.foto_evidencia_url))
            nid = cursor.fetchone()['id']
            conn.commit()
            return {"mensaje": "Solicitud creada", "servicio_id": str(nid)}
    except Exception as e: conn.rollback(); log.error(e); raise HTTPException(500, "Error crear servicio")

@app.get("/servicios/{usuario_id}")
def listar_servicios_cliente(usuario_id: str):
    """Lista todos los servicios solicitados por un cliente (mis solicitudes + mis trabajos activos)."""
    conn = db_connections.get("pg_conn")
    if conn is None:
        raise HTTPException(503, "Base de datos no disponible")
    
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT s.id, s.titulo, s.estado, s.fecha_solicitud, s.descripcion, s.precio_estimado,
                       c.nombre as categoria,
                       (SELECT COUNT(*) FROM propuestas p WHERE p.servicio_id = s.id) as num_propuestas,
                       u_trabajador.id as trabajador_id,
                       u_trabajador.nombre as trabajador_nombre,
                       u_trabajador.telefono as trabajador_telefono,
                       u_cliente.telefono as cliente_telefono,
                       dt.descripcion_bio as trabajador_bio,
                       dt.calificacion_promedio as trabajador_calificacion,
                       dt.total_evaluaciones as trabajador_num_evaluaciones,
                       COALESCE(s.direccion_texto, 'Ubicación en mapa') as direccion_texto,
                       COALESCE(s.calificacion, 0) as calificacion,
                       COALESCE(s.resena, '') as resena
                FROM servicios s
                JOIN categorias_oficios c ON s.categoria_id = c.id
                LEFT JOIN usuarios u_trabajador ON s.trabajador_id = u_trabajador.id
                LEFT JOIN detalles_trabajador dt ON u_trabajador.id = dt.usuario_id
                JOIN usuarios u_cliente ON s.cliente_id = u_cliente.id
                WHERE s.cliente_id = %s
                ORDER BY CASE WHEN s.estado IN ('SOLICITADO', 'EN_PROCESO') THEN 0 ELSE 1 END, s.fecha_solicitud DESC
            """, (usuario_id,))
            
            res = []
            for s in cur.fetchall():
                d = dict(s)
                d['id'] = str(d['id'])
                d['fecha_solicitud'] = str(d['fecha_solicitud'])
                d['trabajador_id'] = str(d['trabajador_id']) if d['trabajador_id'] else None
                d['precio_estimado'] = float(d['precio_estimado']) if d['precio_estimado'] else 0
                d['calificacion'] = int(d['calificacion']) if d['calificacion'] else 0
                d['trabajador_calificacion'] = float(d['trabajador_calificacion']) if d['trabajador_calificacion'] else 0
                res.append(d)
            return res
    except Exception as e:
        log.error(f"Error en /servicios/{{usuario_id}}: {e}")
        raise HTTPException(500, f"Error cargando servicios: {str(e)}")

@app.get("/feed-servicios")
def feed_servicios():
    """Feed de servicios disponibles para que trabajadores se postulen."""
    conn = db_connections.get("pg_conn")
    if conn is None:
        raise HTTPException(503, "Base de datos no disponible")
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT s.id, s.titulo, s.descripcion, s.precio_estimado, s.fecha_programada, s.fecha_solicitud,
                       s.direccion_texto, s.foto_evidencia_url,
                       c.nombre as categoria, 
                       u.id as cliente_id,
                       u.nombre as cliente_nombre,
                       u.telefono as cliente_telefono,
                       (SELECT COUNT(*) FROM propuestas p WHERE p.servicio_id = s.id) as num_propuestas
                FROM servicios s
                JOIN categorias_oficios c ON s.categoria_id = c.id
                JOIN usuarios u ON s.cliente_id = u.id
                WHERE s.estado = 'SOLICITADO'
                ORDER BY s.fecha_solicitud DESC LIMIT 50
            """)
            
            servicios = cursor.fetchall()
            res = []
            for s in servicios:
                d = dict(s)
                d['id'] = str(d['id'])
                d['cliente_id'] = str(d['cliente_id']) if d['cliente_id'] else None
                d['fecha_programada'] = str(d['fecha_programada']) if d['fecha_programada'] else None
                d['fecha_solicitud'] = str(d['fecha_solicitud']) if d['fecha_solicitud'] else None
                d['precio_estimado'] = float(d['precio_estimado']) if d['precio_estimado'] else 0
                res.append(d)
            
            return res
    except Exception as e:
        log.error(f"Error en /feed-servicios: {e}")
        raise HTTPException(500, f"Error cargando feed: {str(e)}")

@app.post("/propuestas")
def crear_propuesta(datos: CrearPropuesta):
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1 FROM propuestas WHERE servicio_id = %s AND trabajador_id = %s", (datos.servicio_id, datos.trabajador_id))
            if cursor.fetchone(): raise HTTPException(400, "Ya te has postulado.")
            cursor.execute("INSERT INTO propuestas (servicio_id, trabajador_id, precio_oferta, mensaje) VALUES (%s, %s, %s, %s)", (datos.servicio_id, datos.trabajador_id, datos.precio_oferta, datos.mensaje))
            conn.commit()
            return {"mensaje": "Propuesta enviada"}
    except HTTPException as e: raise e
    except Exception as e: conn.rollback(); log.error(e); raise HTTPException(500, "Error propuesta")

@app.get("/servicios/{servicio_id}/propuestas")
def ver_propuestas(servicio_id: str):
    """Obtiene todas las propuestas de trabajadores para un servicio específico."""
    conn = db_connections.get("pg_conn")
    if conn is None:
        raise HTTPException(503, "Base de datos no disponible")
    
    try:
        with conn.cursor() as cur:
            # Traemos datos completos del trabajador
            cur.execute("""
                SELECT p.id, p.precio_oferta, p.mensaje, p.trabajador_id,
                       u.nombre, u.apellidos, u.foto_perfil_url, u.telefono,
                       dt.calificacion_promedio, dt.total_evaluaciones,
                       dt.anios_experiencia, dt.descripcion_bio
                FROM propuestas p
                JOIN usuarios u ON p.trabajador_id = u.id
                LEFT JOIN detalles_trabajador dt ON u.id = dt.usuario_id
                WHERE p.servicio_id = %s
                ORDER BY p.precio_oferta ASC
            """, (servicio_id,))
            
            # Convertimos a lista de diccionarios
            resultados = []
            for row in cur.fetchall():
                d = dict(row)
                d['id'] = str(d['id'])
                d['trabajador_id'] = str(d['trabajador_id']) if d['trabajador_id'] else None
                # Convertimos decimales a float para que JS no falle
                if d.get('calificacion_promedio'):
                    d['calificacion_promedio'] = float(d['calificacion_promedio'])
                else:
                    d['calificacion_promedio'] = 0
                if d.get('precio_oferta'):
                    d['precio_oferta'] = float(d['precio_oferta'])
                else:
                    d['precio_oferta'] = 0
                d['anios_experiencia'] = int(d['anios_experiencia']) if d.get('anios_experiencia') else 0
                d['total_evaluaciones'] = int(d['total_evaluaciones']) if d.get('total_evaluaciones') else 0
                resultados.append(d)
            
            return resultados
    except Exception as e:
        log.error(f"Error en /servicios/{{servicio_id}}/propuestas: {e}")
        raise HTTPException(500, f"Error cargando propuestas: {str(e)}")

@app.get("/trabajador/mis-trabajos/{trabajador_id}")
def mis_trabajos_trabajador(trabajador_id: str):
    """Obtiene todos los trabajos asignados a un trabajador (activos + completados)."""
    conn = db_connections.get("pg_conn")
    if conn is None:
        raise HTTPException(503, "Base de datos no disponible")
    
    try:
        with conn.cursor() as cursor:
            # Obtener trabajos con información completa
            cursor.execute("""
                SELECT s.id, s.titulo, s.descripcion, s.estado, s.fecha_solicitud, s.direccion_texto, 
                       s.precio_estimado, s.calificacion, s.resena,
                       u.id as cliente_id, u.nombre as cliente_nombre, u.telefono as cliente_telefono,
                       c.nombre as categoria
                FROM servicios s
                JOIN usuarios u ON s.cliente_id = u.id
                LEFT JOIN categorias_oficios c ON s.categoria_id = c.id
                WHERE s.trabajador_id = %s
                ORDER BY CASE WHEN s.estado = 'EN_PROCESO' THEN 0 ELSE 1 END, s.fecha_solicitud DESC
            """, (trabajador_id,))
            
            resultados = []
            for row in cursor.fetchall():
                d = dict(row)
                d['id'] = str(d['id'])
                d['cliente_id'] = str(d['cliente_id']) if d['cliente_id'] else None
                d['fecha_solicitud'] = str(d['fecha_solicitud'])
                d['precio_estimado'] = float(d['precio_estimado']) if d['precio_estimado'] else 0
                d['calificacion'] = int(d['calificacion']) if d['calificacion'] else 0
                resultados.append(d)
            
            return resultados
    except Exception as e:
        log.error(f"Error en /trabajador/mis-trabajos: {e}")
        raise HTTPException(500, f"Error cargando trabajos: {str(e)}")


@app.get("/servicio/{servicio_id}")
def obtener_servicio_por_id(servicio_id: str):
    """Devuelve un único servicio con información del trabajador y cliente."""
    conn = db_connections.get("pg_conn")
    if conn is None:
        raise HTTPException(503, "Base de datos no disponible.")
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT s.id, s.titulo, s.estado, s.fecha_solicitud, s.descripcion, s.precio_estimado,
                       c.nombre as categoria,
                       u_trabajador.id as trabajador_id,
                       u_trabajador.nombre as trabajador_nombre,
                       u_trabajador.telefono as trabajador_telefono,
                       u_cliente.id as cliente_id,
                       u_cliente.nombre as cliente_nombre,
                       u_cliente.telefono as cliente_telefono,
                       dt.descripcion_bio as trabajador_bio,
                       dt.calificacion_promedio as trabajador_calificacion,
                       dt.total_evaluaciones as trabajador_num_evaluaciones,
                       COALESCE(s.direccion_texto, 'Ubicación en mapa') as direccion_texto
                FROM servicios s
                JOIN categorias_oficios c ON s.categoria_id = c.id
                LEFT JOIN usuarios u_trabajador ON s.trabajador_id = u_trabajador.id
                LEFT JOIN detalles_trabajador dt ON u_trabajador.id = dt.usuario_id
                LEFT JOIN usuarios u_cliente ON s.cliente_id = u_cliente.id
                WHERE s.id = %s
            """, (servicio_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Servicio no encontrado.")
            s = dict(row)
            s['id'] = str(s['id'])
            s['trabajador_id'] = str(s['trabajador_id']) if s.get('trabajador_id') else None
            s['cliente_id'] = str(s['cliente_id']) if s.get('cliente_id') else None
            s['fecha_solicitud'] = str(s['fecha_solicitud'])
            return s
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error obteniendo servicio: {e}")
        raise HTTPException(500, "Error interno")

@app.post("/servicios/finalizar")
def finalizar_servicio(datos: CalificarServicio):
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE servicios SET estado = 'TERMINADO', calificacion = %s, resena = %s WHERE id = %s RETURNING trabajador_id", (datos.calificacion, datos.resena, datos.servicio_id))
            res = cursor.fetchone()
            if not res: raise HTTPException(404, "Servicio no encontrado")
            tid = res['trabajador_id']
            cursor.execute("SELECT AVG(calificacion) as pro, COUNT(*) as tot FROM servicios WHERE trabajador_id = %s AND calificacion IS NOT NULL", (tid,))
            stats = cursor.fetchone()
            cursor.execute("UPDATE detalles_trabajador SET calificacion_promedio = %s, total_evaluaciones = %s WHERE usuario_id = %s", (float(stats['pro'] or 0), int(stats['tot']), tid))
            conn.commit()
            return {"mensaje": "Finalizado y calificado"}
    except Exception as e: conn.rollback(); log.error(e); raise HTTPException(500, "Error finalizar")


# --- ENDPOINT PARA MARCAR SERVICIO COMO COMPLETADO ---
@app.post("/servicios/{servicio_id}/completar")
def completar_servicio(servicio_id: str, datos: CalificarServicio = None):
    """
    Marca un servicio como TERMINADO y guarda la calificación del cliente.
    También actualiza la calificación promedio del trabajador.
    """
    conn = db_connections.get("pg_conn")
    if conn is None:
        raise HTTPException(503, "Base de datos no disponible.")
    
    try:
        with conn.cursor() as cursor:
            # 1. Verificar que el servicio existe y obtener trabajador_id
            cursor.execute(
                "SELECT id, estado, trabajador_id FROM servicios WHERE id = %s",
                (servicio_id,)
            )
            servicio = cursor.fetchone()
            
            if not servicio:
                raise HTTPException(404, "Servicio no encontrado.")
            
            if servicio['estado'] == 'TERMINADO':
                raise HTTPException(400, "El servicio ya está terminado.")
            
            trabajador_id = servicio['trabajador_id']
            calificacion = datos.calificacion if datos else None
            resena = datos.resena if datos else None
            
            # 2. Actualizar servicio con calificación y reseña
            cursor.execute("""
                UPDATE servicios 
                SET estado = 'TERMINADO', 
                    calificacion = %s, 
                    resena = %s
                WHERE id = %s
                RETURNING id
            """, (calificacion, resena, servicio_id))
            
            update_result = cursor.fetchone()
            
            if not update_result:
                conn.rollback()
                raise HTTPException(500, "No se pudo actualizar el servicio")
            
            # 3. Si hay trabajador, actualizar su calificación promedio
            if trabajador_id:
                cursor.execute("""
                    SELECT AVG(calificacion) as promedio, COUNT(*) as total
                    FROM servicios 
                    WHERE trabajador_id = %s AND calificacion IS NOT NULL
                """, (trabajador_id,))
                
                stats = cursor.fetchone()
                if stats and stats['promedio'] is not None:
                    promedio = float(stats['promedio'])
                    total = int(stats['total'])
                    
                    # Actualizar detalles del trabajador con su nuevo promedio
                    cursor.execute("""
                        UPDATE detalles_trabajador 
                        SET calificacion_promedio = %s, 
                            total_evaluaciones = %s
                        WHERE usuario_id = %s
                        RETURNING usuario_id
                    """, (promedio, total, trabajador_id))
                    
                    trabajador_update = cursor.fetchone()
                    
                    if trabajador_update:
                        log.info(f"✅ Trabajador {trabajador_id} actualizado:")
                        log.info(f"   - Nueva calificación: {promedio:.2f}/5")
                        log.info(f"   - Total evaluaciones: {total}")
                    else:
                        log.warning(f"⚠️ No se pudo actualizar calificaciones del trabajador {trabajador_id}")
            
            conn.commit()
            
            log.info(f"✅ Servicio {servicio_id} completado:")
            log.info(f"   - Estado: TERMINADO")
            log.info(f"   - Calificación: {calificacion}/5")
            log.info(f"   - Reseña: {resena if resena else 'Sin reseña'}")
            
            return {
                "mensaje": "Servicio completado y calificado correctamente",
                "estado": "TERMINADO",
                "calificacion": calificacion,
                "resena": resena
            }
    
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        log.error(f"❌ Error completando servicio: {e}")
        raise HTTPException(500, f"Error completando servicio: {str(e)}")
        raise HTTPException(500, "Error al completar servicio")

# ==========================================
# 8. ADMIN
# ==========================================
@app.get("/admin/usuarios")
def admin_listar_usuarios():
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cursor:
            cursor.execute("""SELECT u.id, u.nombre, u.apellidos, u.correo_electronico, u.activo, u.bloqueado_hasta, CASE WHEN dt.usuario_id IS NOT NULL THEN 'Trabajador' WHEN dc.usuario_id IS NOT NULL THEN 'Cliente' WHEN u.es_admin THEN 'Admin' ELSE 'Desconocido' END as rol, dt.validado_por_admin FROM usuarios u LEFT JOIN detalles_trabajador dt ON u.id = dt.usuario_id LEFT JOIN detalles_cliente dc ON u.id = dc.usuario_id ORDER BY u.fecha_registro DESC""")
            return [dict(u, id=str(u['id']), bloqueado_hasta=str(u['bloqueado_hasta']) if u['bloqueado_hasta'] else None) for u in cursor.fetchall()]
    except Exception as e: log.error(e); raise HTTPException(500, "Error listando")

@app.post("/admin/accion")
def admin_accion_usuario(datos: AccionAdmin):
    conn = db_connections.get("pg_conn")
    try:
        with conn.cursor() as cursor:
            if datos.accion == "validar": cursor.execute("UPDATE detalles_trabajador SET validado_por_admin = TRUE WHERE usuario_id = %s", (datos.usuario_id,))
            elif datos.accion == "bloquear":
                dias = datos.dias_bloqueo if datos.dias_bloqueo else 36500
                fecha_fin = datetime.now() + timedelta(days=dias)
                cursor.execute("UPDATE usuarios SET bloqueado_hasta = %s WHERE id = %s", (fecha_fin, datos.usuario_id))
            elif datos.accion == "desbloquear": cursor.execute("UPDATE usuarios SET bloqueado_hasta = NULL WHERE id = %s", (datos.usuario_id,))
            elif datos.accion == "borrar": cursor.execute("DELETE FROM usuarios WHERE id = %s", (datos.usuario_id,))
            conn.commit()
            return {"mensaje": f"Acción '{datos.accion}' ejecutada."}
    except Exception as e: conn.rollback(); log.error(e); raise HTTPException(500, f"Error: {str(e)}")


@app.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    event = None

    # Validar que tenemos la clave del webhook
    if not STRIPE_WEBHOOK_SECRET or STRIPE_WEBHOOK_SECRET == "whsec_test_secret_para_desarrollo":
        log.warning("⚠️ WEBHOOK: STRIPE_WEBHOOK_SECRET no está configurada correctamente. Usando modo de prueba.")
        # En modo test, aceptamos sin verificar firma
        try:
            import json
            event = json.loads(payload)
        except Exception as e:
            log.error(f"Error parsing JSON payload: {e}")
            raise HTTPException(400, "Invalid payload")
    else:
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )
        except ValueError as e:
            log.error(f"Invalid payload: {e}")
            raise HTTPException(400, "Invalid payload")
        except stripe.error.SignatureVerificationError as e:
            log.error(f"Invalid signature: {e}")
            raise HTTPException(400, "Invalid signature")

    # Handle the event
    if event and event.get('type') == 'checkout.session.completed':
        session = event['data']['object']
        
        # Recuperar metadata
        metadata = session.get('metadata', {})
        servicio_id = metadata.get('servicio_id')
        propuesta_id = metadata.get('propuesta_id')
        trabajador_id = metadata.get('trabajador_id')
        precio_pagado = session.get('amount_total', 0) / 100.0 # Stripe viene en centavos

        if servicio_id and propuesta_id and trabajador_id:
            conn = db_connections.get("pg_conn")
            try:
                with conn.cursor() as cursor:
                    # 1. Actualizar Servicio: Asignar trabajador y poner en proceso
                    cursor.execute("""
                        UPDATE servicios 
                        SET trabajador_id = %s, estado = 'EN_PROCESO', precio_estimado = %s 
                        WHERE id = %s
                    """, (trabajador_id, precio_pagado, servicio_id))
                    
                    # 2. Marcar Propuesta como aceptada
                    cursor.execute("""
                        UPDATE propuestas 
                        SET aceptada = TRUE 
                        WHERE id = %s
                    """, (propuesta_id,))
                    
                    conn.commit()
                    log.info(f"✅ PAGO CONFIRMADO: Servicio {servicio_id} asignado a {trabajador_id}")
                    return {"status": "success", "message": "Pago procesado correctamente"}
            except Exception as e:
                conn.rollback()
                log.error(f"❌ Error actualizando BD tras pago: {e}")
                return {"status": "error", "message": "Database update failed"}
        else:
            log.warning(f"⚠️ WEBHOOK: Metadata incompleta. servicio_id={servicio_id}, propuesta_id={propuesta_id}, trabajador_id={trabajador_id}")

    return {"status": "success"}