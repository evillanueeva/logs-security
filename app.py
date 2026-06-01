"""""
PROYECTO: Desafio MELI - Developer IA
DESCRIPCIÓN: Agente de detección de anomalías de accesos
AUTOR: Emanuel Villanueva
"""""
import numpy as np
import pandas as pd
import time
from collections import defaultdict
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Any
from datetime import datetime

app = FastAPI(
    title="Desafio MELI - EMANUEL VILLANUEVA",
    description="Módulo Backend con detección de anomalías y agentes con correlación temporal.",
    version="1.1.0"
)

# --- MODELO DE IA ---
model = IsolationForest(contamination=0.1, random_state=42)

@app.on_event("startup")
def train_base_model():
    #Simulación de entrenamiento con datos ficticios#
    normal_data = []
    for _ in range(200):
        status = np.random.choice([200, 204, 302])
        size = np.random.randint(200, 5000)
        hour = np.random.randint(8, 18)
        normal_data.append([status, size, hour])
    
    anomalous_data = [
        [500, 500000, 3],
        [403, 0, 1],
    ]
    
    X = np.vstack([normal_data, anomalous_data])
    model.fit(X)
    print("Modelo Isolation Forest entrenado exitosamente con datos base.")


# --- MODELOS DE DATOS ---
class LogEntry(BaseModel):
    ip: str
    timestamp: str  
    method: str
    path: str
    status_code: int
    response_size: int

class AnalysisResponse(BaseModel):
    total_processed: int
    threats_detected: int
    results: List[Dict[str, Any]]


# --- CACHE DE MEMORIA COMPARTIDA (Simula un clúster de Redis) ***
# Guarda los timestamps de las anomalías detectadas por IP: { "IP": [t1, t2, ...] }
redis_mock_cache = defaultdict(list)


# --- AGENTES ---

class LogIngestionAgent:
    """Agente encargado de recibir, limpiar y transformar los logs en vectores numéricos."""
    
    @staticmethod
    def process(logs: List[LogEntry]) -> pd.DataFrame:
        processed_features = []
        for log in logs:
            try:
                dt = datetime.strptime(log.timestamp, "%Y-%m-%d %H:%M:%S")
                hour = dt.hour
            except ValueError:
                hour = 12  # Valor por defecto ante fallos de parsing
            
            processed_features.append({
                "status_code": log.status_code,
                "response_size": log.response_size,
                "hour": hour
            })
        return pd.DataFrame(processed_features)


class DecisionAgent:
    """Agente de Decisión Avanzado: Evalúa la anomalía y correlaciona 
    el comportamiento histórico de la IP en tiempo real (Ventana Deslizante)."""
    
    LIMIT_WINDOW_SECONDS = 60  # Ventana de tiempo a vigilar (1 minuto)
    MAX_ATTEMPTS_ALLOWED = 3   # Máximo de anomalías toleradas antes del bloqueo total

    @classmethod
    def evaluate(cls, log: LogEntry, is_anomaly: bool) -> Dict[str, Any]:
        current_time = time.time()
        ip = log.ip
        
        # 1. Si la IA determina que es normal, permitimos el tráfico
        if not is_anomaly:
            return {
                "log": log.dict(),
                "is_threat": False,
                "confidence": "High",
                "suggested_action": "ALLOW"
            }
        
        # 2. La IA detectó anomalía: Registramos el evento en memoria compartida
        redis_mock_cache[ip].append(current_time)
        
        # 3. Limpieza: Eliminamos registros que superen la ventana de 60 segundos
        redis_mock_cache[ip] = [
            t for t in redis_mock_cache[ip] 
            if current_time - t <= cls.LIMIT_WINDOW_SECONDS
        ]
        
        # 4. Calculamos la recurrencia actual del atacante
        recent_anomalies_count = len(redis_mock_cache[ip])
        
        # 5. Mitigación inteligente basada en contexto e historial
        action = "ALERT"
        reason = f"Comportamiento estadísticamente inusual. Anomalías acumuladas en el último minuto: {recent_anomalies_count}."
        
        # Umbral crítico por reincidencia (Fuerza bruta / Escaneo de vulnerabilidades)
        if recent_anomalies_count >= cls.MAX_ATTEMPTS_ALLOWED:
            action = "BLOCK"
            reason = f"BLOQUEO CRÍTICO: Patrón de ataque persistente detectado. La IP acumuló {recent_anomalies_count} anomalías consecutivas en menos de 60 segundos."
        
        # Umbral crítico por severidad inmediata 
        elif log.status_code in [401, 403] and log.response_size > 100000:
            action = "BLOCK"
            reason = "Intento de exfiltración masiva o acceso prohibido de gran volumen detectado en un solo evento."

        return {
            "log": log.dict(),
            "is_threat": True,
            "confidence": "High",
            "suggested_action": action,
            "reason": reason,
            "metrics": {
                "anomalies_in_window": recent_anomalies_count,
                "window_seconds": cls.LIMIT_WINDOW_SECONDS
            }
        }


# --- ENDPOINTS ---

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_logs(logs: List[LogEntry]):
    if not logs:
        raise HTTPException(status_code=400, detail="El lote de logs no puede estar vacío.")
    
    # 1. Procesamiento de características mediante el Agente de Ingestión
    features_df = LogIngestionAgent.process(logs)
    
    # 2. Predicción en bloque con el modelo Isolation Forest (-1 = Anomalía, 1 = Normal)
    predictions = model.predict(features_df.values)
    
    # 3. Orquestación y evaluación secuencial en el Agente de Decisión
    final_results = []
    threats_count = 0
    
    for idx, log in enumerate(logs):
        is_anomaly = True if predictions[idx] == -1 else False
        decision = DecisionAgent.evaluate(log, is_anomaly)
        
        if decision["is_threat"]:
            threats_count += 1
            
        final_results.append(decision)
        
    return {
        "total_processed": len(logs),
        "threats_detected": threats_count,
        "results": final_results
    }

# Sitio web inicio
@app.get("/", response_class=HTMLResponse)
def welcome_page():
    html_content = """
    

    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Desafio MELI EV</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-900 text-slate-100 min-h-screen flex items-center justify-center font-sans">
        <div class="max-w-xl w-full mx-4 bg-slate-800 p-8 rounded-2xl shadow-2xl border border-slate-700 text-center">
            
            <div class="inline-flex px-6 py-3 bg-[#FFF000] rounded-2xl mb-6 shadow-md">
            <img src="https://logodownload.org/wp-content/uploads/2018/10/mercado-libre-logo-1.png" 
            alt="Mercado Libre" 
            class="h-12 w-auto object-contain">
</div>

            <h1 class="text-3xl font-extrabold text-white tracking-tight">Análisis de seguridad con IA</h1>
            <p class="text-slate-400 mt-2 text-sm">Detección inteligente de comportamientos anómalos de accesos.</p>

            <div class="mt-6 inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-emerald-500/10 text-emerald-400 text-xs font-semibold border border-emerald-500/20">
                <span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                SISTEMA OPERATIVO
            </div>

            <hr class="border-slate-700 my-6">

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <a href="/docs" class="flex flex-col items-center justify-center p-4 bg-slate-700/50 hover:bg-slate-700 rounded-xl border border-slate-600 hover:border-amber-500 transition-all group">
                    <span class="font-bold text-white group-hover:text-amber-400 text-base">Swagger UI</span>
                    <span class="text-xs text-slate-400 mt-1">Documentación interactiva</span>
                </a>
                <a href="/redoc" class="flex flex-col items-center justify-center p-4 bg-slate-700/50 hover:bg-slate-700 rounded-xl border border-slate-600 hover:border-amber-500 transition-all group">
                    <span class="font-bold text-white group-hover:text-amber-400 text-base">ReDoc</span>
                    <span class="text-xs text-slate-400 mt-1">Especificación técnica</span>
                </a>
            </div>

            <p class="text-slate-500 text-xs mt-8">Desafío Técnico - Mercado Libre - Emanuel Villanueva</p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)