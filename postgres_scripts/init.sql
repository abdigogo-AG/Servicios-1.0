-- Conectarse a la base de datos
-- \c registros;

-- Habilitar extensión para funciones criptográficas (Opcional pero útil)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ==========================================
-- 1. CATÁLOGOS (OFICIOS)
-- ==========================================
CREATE TABLE categorias_oficios (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(50) UNIQUE NOT NULL,
    icono_url TEXT 
);

-- Insertar oficios por defecto
INSERT INTO categorias_oficios (nombre, icono_url) VALUES 
    ('Plomero', 'fas fa-wrench'), 
    ('Electricista', 'fas fa-bolt'), 
    ('Carpintero', 'fas fa-hammer'), 
    ('Jardinero', 'fas fa-leaf'), 
    ('Pintor', 'fas fa-paint-roller'), 
    ('Albañil', 'fas fa-trowel'),
    ('Limpieza', 'fas fa-broom'),
    ('Mecánico', 'fas fa-car-wrench')
ON CONFLICT DO NOTHING;

-- ==========================================
-- 2. USUARIOS (TABLA MAESTRA)
-- ==========================================
CREATE TABLE usuarios (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nombre VARCHAR(100) NOT NULL,
    apellidos VARCHAR(255) NOT NULL,
    correo_electronico VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    telefono VARCHAR(20) NOT NULL,
    fecha_nacimiento DATE, 
    foto_perfil_url TEXT,
    fecha_registro TIMESTAMPTZ DEFAULT NOW(),
    
    activo BOOLEAN DEFAULT FALSE,
    codigo_verificacion VARCHAR(6),

    -- SEGURIDAD Y ADMIN
    es_admin BOOLEAN DEFAULT FALSE,
    bloqueado_hasta TIMESTAMPTZ DEFAULT NULL 
);

-- ==========================================
-- 3. DETALLES DEL CLIENTE
-- ==========================================
CREATE TABLE detalles_cliente (
    usuario_id UUID PRIMARY KEY REFERENCES usuarios(id) ON DELETE CASCADE,
    calle VARCHAR(255),
    colonia VARCHAR(100),
    numero_exterior VARCHAR(20),
    numero_interior VARCHAR(20),
    referencias_domicilio TEXT,
    codigo_postal VARCHAR(10),
    ciudad VARCHAR(100),
    
    -- Ubicación GPS
    latitud DECIMAL(9,6),
    longitud DECIMAL(9,6),
    
    id_cliente_pagos VARCHAR(100) 
);

-- ==========================================
-- 4. DETALLES DEL TRABAJADOR
-- ==========================================
CREATE TABLE detalles_trabajador (
    usuario_id UUID PRIMARY KEY REFERENCES usuarios(id) ON DELETE CASCADE,
    
    -- Perfil Profesional
    descripcion_bio TEXT,
    anios_experiencia INT,
    tarifa_hora_estimada DECIMAL(10,2),
    
    -- Documentación Legal
    foto_ine_frente_url TEXT,
    foto_ine_reverso_url TEXT,
    antecedentes_penales_url TEXT,
    validado_por_admin BOOLEAN DEFAULT TRUE,
    
    -- Ubicación Base
    latitud DECIMAL(9,6),
    longitud DECIMAL(9,6),
    radio_cobertura_km INT DEFAULT 10,
    
    disponible BOOLEAN DEFAULT TRUE,
    
    -- Reputación
    calificacion_promedio DECIMAL(3, 2) DEFAULT 0, 
    total_evaluaciones INT DEFAULT 0
);

-- ==========================================
-- 5. RELACIÓN TRABAJADOR <-> OFICIOS
-- ==========================================
CREATE TABLE trabajador_oficios (
    usuario_id UUID REFERENCES detalles_trabajador(usuario_id) ON DELETE CASCADE,
    categoria_id INT REFERENCES categorias_oficios(id) ON DELETE CASCADE,
    PRIMARY KEY (usuario_id, categoria_id)
);

-- ==========================================
-- 6. SERVICIOS (TRABAJOS)
-- ==========================================
CREATE TYPE estado_servicio AS ENUM ('SOLICITADO', 'ACEPTADO', 'EN_PROCESO', 'TERMINADO', 'CANCELADO');

CREATE TABLE servicios (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Relaciones
    cliente_id UUID REFERENCES detalles_cliente(usuario_id) NOT NULL,
    trabajador_id UUID REFERENCES detalles_trabajador(usuario_id), -- NULL al principio
    categoria_id INT REFERENCES categorias_oficios(id),
    
    -- Detalles
    titulo VARCHAR(150),
    descripcion TEXT,
    foto_evidencia_url TEXT,
    
    -- Ubicación (Snapshot)
    direccion_texto TEXT,
    latitud DECIMAL(9,6),
    longitud DECIMAL(9,6),
    
    -- Tiempos y Costos
    fecha_solicitud TIMESTAMPTZ DEFAULT NOW(),
    fecha_programada TIMESTAMPTZ,
    precio_estimado DECIMAL(10,2),
    
    -- Finalización
    calificacion INT DEFAULT NULL,
    resena TEXT DEFAULT NULL,
    
    estado estado_servicio DEFAULT 'SOLICITADO'
);

-- ==========================================
-- 7. PROPUESTAS (POSTULACIONES)
-- ==========================================
CREATE TABLE propuestas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    servicio_id UUID REFERENCES servicios(id) ON DELETE CASCADE,
    trabajador_id UUID REFERENCES detalles_trabajador(usuario_id) ON DELETE CASCADE,
    mensaje TEXT, 
    precio_oferta DECIMAL(10,2),
    aceptada BOOLEAN DEFAULT FALSE,
    fecha_creacion TIMESTAMPTZ DEFAULT NOW()
);

-- ==========================================
-- 8. ÍNDICES
-- ==========================================
CREATE INDEX IF NOT EXISTS idx_correo ON usuarios (correo_electronico);
CREATE INDEX IF NOT EXISTS idx_servicios_cliente ON servicios(cliente_id);
CREATE INDEX IF NOT EXISTS idx_servicios_trabajador ON servicios(trabajador_id);
CREATE INDEX IF NOT EXISTS idx_servicios_estado ON servicios(estado);
CREATE INDEX IF NOT EXISTS idx_propuestas_servicio ON propuestas(servicio_id);