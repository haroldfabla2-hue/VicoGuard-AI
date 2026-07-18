"""
VicoGuard AI - Multi-Agent Security Team
=========================================
Inspirado en agent-team (github.com/haroldfabla2-hue/agent-team)
Implementa un equipo de 4 agentes especializados con protocolo de
orquestacion y handoff entre especialistas.

Arquitectura:
    Orchestrator
      |-- SecOps Auditor    (escaneo estatico)
      |-- Threat Analyst    (correlacion de logs)
      |-- Remediation Arch  (generacion de parches)
"""

import json
import time
import logging
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("vicoguard.agents")


# ═══════════════════════════════════════════
# AGENT DEFINITIONS (Protocolo de Equipo)
# ═══════════════════════════════════════════

class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    SECOPS_AUDITOR = "secops_auditor"
    THREAT_ANALYST = "threat_analyst"
    REMEDIATION_ARCHITECT = "remediation_architect"


class TaskStatus(str, Enum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    HANDED_OFF = "handed_off"


@dataclass
class AgentTask:
    """Una tarea asignada a un agente especialista."""
    id: str
    role: AgentRole
    input_data: Dict[str, Any]
    output_data: Optional[Dict[str, Any]] = None
    status: TaskStatus = TaskStatus.QUEUED
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None


@dataclass
class AgentProfile:
    """Perfil de un agente con su system prompt especializado."""
    role: AgentRole
    name: str
    system_prompt: str
    temperature: float = 0.3
    max_tokens: int = 1024


# ═══════════════════════════════════════════
# SYSTEM PROMPTS ESPECIALIZADOS POR AGENTE
# ═══════════════════════════════════════════

AGENT_PROFILES = {
    AgentRole.SECOPS_AUDITOR: AgentProfile(
        role=AgentRole.SECOPS_AUDITOR,
        name="SecOps Auditor",
        system_prompt="""Eres un auditor de seguridad especializado en aplicaciones web.
Tu trabajo es analizar los resultados de escaneos estaticos y clasificar cada hallazgo.

REGLAS:
- Clasifica cada hallazgo con severity: critical, high, medium, low
- Para cada hallazgo genera un "finding_id" unico
- Identifica el tipo exacto de vulnerabilidad (CWE si es posible)
- NO generes remediaciones, solo diagnosticos

Responde UNICAMENTE en JSON valido con esta estructura:
{
  "findings": [
    {
      "finding_id": "F001",
      "type": "SUPABASE_RLS_DISABLED",
      "severity": "critical",
      "description": "...",
      "affected_resource": "tabla: users",
      "cwe": "CWE-862"
    }
  ],
  "risk_score": 0-100,
  "summary": "Resumen ejecutivo en 1 linea"
}""",
        temperature=0.1,
        max_tokens=2048
    ),

    AgentRole.THREAT_ANALYST: AgentProfile(
        role=AgentRole.THREAT_ANALYST,
        name="Threat Analyst",
        system_prompt="""Eres un analista de amenazas especializado en correlacion de logs de servidor.

Tu trabajo es:
1. Filtrar el RUIDO (bots, crawlers, 404s normales) del PELIGRO REAL
2. Identificar patrones de ataque (fuerza bruta, DDoS, inyeccion SQL, port scanning)
3. Calcular un Security Score de 0-100

REGLAS:
- Si hay mas de 10 requests fallidos desde la misma IP en 60s = FUERZA BRUTA
- Si hay mas de 100 requests en 10s = DDoS potencial
- Si hay requests a /.env, /wp-admin, /xmlrpc.php = RECONNAISSANCE
- Los 404 de bots normales (Googlebot, Bingbot) NO son amenazas

Responde UNICAMENTE en JSON valido:
{
  "attacks_detected": [
    {
      "attack_id": "A001",
      "type": "brute_force",
      "severity": "high",
      "source_ips": ["1.2.3.4"],
      "target_paths": ["/admin/login"],
      "event_count": 500,
      "time_window_seconds": 60,
      "confidence": 0.95
    }
  ],
  "noise_filtered": 42,
  "security_score": 35,
  "situation_summary": "Resumen en lenguaje SIMPLE para un no-tecnico"
}""",
        temperature=0.2,
        max_tokens=2048
    ),

    AgentRole.REMEDIATION_ARCHITECT: AgentProfile(
        role=AgentRole.REMEDIATION_ARCHITECT,
        name="Remediation Architect",
        system_prompt="""Eres un arquitecto de remediacion de seguridad. Tu trabajo es generar
soluciones CONCRETAS y EJECUTABLES para vulnerabilidades y ataques detectados.

REGLAS:
1. Genera comandos REALES de bash, SQL, o configuracion que el usuario pueda copiar-pegar
2. Explica cada solucion en lenguaje SIMPLE, como si hablaras con un fundador no-tecnico
3. Usa analogias cotidianas (ej: "Es como cambiar la cerradura de tu casa")
4. Prioriza las soluciones por urgencia

Responde UNICAMENTE en JSON valido:
{
  "protocols": [
    {
      "protocol_id": "P001",
      "title": "Bloquear IP atacante",
      "urgency": "AHORA",
      "plain_language": "Detectamos que alguien esta intentando adivinar tu contrasena...",
      "technical_command": "sudo ufw deny from 185.234.72.15",
      "estimated_fix_time": "30 segundos",
      "risk_if_ignored": "Acceso no autorizado a tu panel de administracion"
    }
  ],
  "overall_status": "CONTENIDO" | "EN_RIESGO" | "COMPROMETIDO",
  "telegram_message": "Mensaje listo para enviar por Telegram en Markdown"
}""",
        temperature=0.4,
        max_tokens=2048
    ),
}


# ═══════════════════════════════════════════
# ORCHESTRATOR ENGINE
# ═══════════════════════════════════════════

class SecurityTeamOrchestrator:
    """
    Orquestador del equipo de agentes de seguridad.
    Coordina el flujo: Scan -> Analysis -> Remediation -> Notification
    Implementa el patron de handoff entre agentes.
    """

    def __init__(self, llm_client=None):
        """
        Args:
            llm_client: Cualquier cliente LLM con metodo chat(system_prompt, user_message) -> str
        """
        self.llm_client = llm_client
        self.profiles = AGENT_PROFILES
        self.task_history: List[AgentTask] = []
        self._task_counter = 0

    def _create_task(self, role: AgentRole, input_data: Dict) -> AgentTask:
        self._task_counter += 1
        return AgentTask(
            id=f"T{self._task_counter:03d}",
            role=role,
            input_data=input_data
        )

    def _dispatch_to_agent(self, task: AgentTask) -> Dict[str, Any]:
        """
        Despacha una tarea a un agente especialista.
        Usa el system prompt especifico del agente + los datos de entrada.
        """
        profile = self.profiles[task.role]
        task.status = TaskStatus.IN_PROGRESS
        task.started_at = time.time()

        logger.info(f"[DISPATCH] {profile.name} -> Task {task.id}")

        try:
            if self.llm_client:
                # Llamar al LLM real con el prompt del agente
                user_message = json.dumps(task.input_data, indent=2, ensure_ascii=False)
                response_text = self.llm_client.chat(
                    system_prompt=profile.system_prompt,
                    user_message=user_message,
                    temperature=profile.temperature,
                    max_tokens=profile.max_tokens
                )
                # Parsear JSON de la respuesta
                task.output_data = json.loads(response_text)
            else:
                # Modo mock para desarrollo/demo
                task.output_data = self._mock_agent_response(task.role, task.input_data)

            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
            logger.info(f"[COMPLETE] {profile.name} -> Task {task.id} ({task.completed_at - task.started_at:.1f}s)")

        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.completed_at = time.time()
            logger.error(f"[FAILED] {profile.name} -> Task {task.id}: {e}")
            task.output_data = {"error": str(e)}

        self.task_history.append(task)
        return task.output_data

    def run_full_pipeline(self, scan_results: Dict, server_logs: str = "") -> Dict[str, Any]:
        """
        Ejecuta el pipeline completo de equipo de agentes:
        1. SecOps Auditor analiza el escaneo
        2. Threat Analyst correlaciona los logs
        3. Remediation Architect genera los parches
        4. Orchestrator consolida el resultado final
        """
        pipeline_start = time.time()
        results = {
            "pipeline_id": f"P{int(time.time())}",
            "started_at": datetime.utcnow().isoformat() if 'datetime' in dir() else "",
            "agents_used": [],
            "audit": None,
            "threat_analysis": None,
            "remediation": None,
            "final_telegram_message": ""
        }

        # STEP 1: SecOps Auditor
        audit_task = self._create_task(AgentRole.SECOPS_AUDITOR, {
            "scan_type": "static_analysis",
            "scan_results": scan_results
        })
        audit_output = self._dispatch_to_agent(audit_task)
        results["audit"] = audit_output
        results["agents_used"].append("SecOps Auditor")

        # STEP 2: Threat Analyst (si hay logs)
        if server_logs:
            threat_task = self._create_task(AgentRole.THREAT_ANALYST, {
                "server_logs": server_logs,
                "audit_context": audit_output  # Handoff: pasar contexto del auditor
            })
            threat_output = self._dispatch_to_agent(threat_task)
            results["threat_analysis"] = threat_output
            results["agents_used"].append("Threat Analyst")
        else:
            threat_output = {}

        # STEP 3: Remediation Architect
        remediation_input = {
            "audit_findings": audit_output.get("findings", []),
            "attacks_detected": threat_output.get("attacks_detected", []),
            "security_score": threat_output.get("security_score", audit_output.get("risk_score", 50))
        }
        remediation_task = self._create_task(AgentRole.REMEDIATION_ARCHITECT, remediation_input)
        remediation_output = self._dispatch_to_agent(remediation_task)
        results["remediation"] = remediation_output
        results["agents_used"].append("Remediation Architect")

        # STEP 4: Consolidar mensaje final de Telegram
        results["final_telegram_message"] = remediation_output.get(
            "telegram_message",
            self._build_fallback_message(audit_output, threat_output, remediation_output)
        )

        pipeline_elapsed = time.time() - pipeline_start
        results["total_pipeline_seconds"] = round(pipeline_elapsed, 2)

        return results

    def _build_fallback_message(self, audit, threat, remediation) -> str:
        score = threat.get("security_score", audit.get("risk_score", "?"))
        status = remediation.get("overall_status", "DESCONOCIDO")
        protocols = remediation.get("protocols", [])

        msg = f"*VicoGuard AI - Reporte de Seguridad*\n\n"
        msg += f"Security Score: *{score}/100*\n"
        msg += f"Estado: *{status}*\n\n"

        if protocols:
            msg += "*Acciones recomendadas:*\n"
            for p in protocols[:3]:
                msg += f"- {p.get('title', 'N/A')}: {p.get('plain_language', '')}\n"

        return msg

    def get_team_status(self) -> Dict:
        """Dashboard del equipo (inspirado en /agent-team:status)."""
        status = {}
        for role, profile in self.profiles.items():
            role_tasks = [t for t in self.task_history if t.role == role]
            completed = [t for t in role_tasks if t.status == TaskStatus.COMPLETED]
            failed = [t for t in role_tasks if t.status == TaskStatus.FAILED]
            avg_time = 0
            if completed:
                avg_time = sum(t.completed_at - t.started_at for t in completed) / len(completed)

            status[profile.name] = {
                "role": role.value,
                "tasks_completed": len(completed),
                "tasks_failed": len(failed),
                "avg_response_seconds": round(avg_time, 2)
            }
        return status

    def _mock_agent_response(self, role: AgentRole, input_data: Dict) -> Dict:
        """Respuestas simuladas para demo sin API key."""
        if role == AgentRole.SECOPS_AUDITOR:
            return {
                "findings": [
                    {
                        "finding_id": "F001",
                        "type": "SUPABASE_RLS_DISABLED",
                        "severity": "critical",
                        "description": "Row Level Security esta deshabilitado en la tabla 'users'. Cualquier usuario autenticado puede leer todos los registros.",
                        "affected_resource": "tabla: users",
                        "cwe": "CWE-862"
                    },
                    {
                        "finding_id": "F002",
                        "type": "SECRET_EXPOSED",
                        "severity": "high",
                        "description": "API key de Supabase expuesta en archivo .env en repositorio publico",
                        "affected_resource": ".env",
                        "cwe": "CWE-798"
                    }
                ],
                "risk_score": 25,
                "summary": "2 vulnerabilidades criticas detectadas: RLS deshabilitado y secreto expuesto"
            }
        elif role == AgentRole.THREAT_ANALYST:
            return {
                "attacks_detected": [
                    {
                        "attack_id": "A001",
                        "type": "brute_force",
                        "severity": "high",
                        "source_ips": ["45.33.49.12"],
                        "target_paths": ["/admin/login"],
                        "event_count": 500,
                        "time_window_seconds": 60,
                        "confidence": 0.95
                    },
                    {
                        "attack_id": "A002",
                        "type": "reconnaissance",
                        "severity": "medium",
                        "source_ips": ["185.234.72.15"],
                        "target_paths": ["/.env", "/wp-admin", "/xmlrpc.php"],
                        "event_count": 4,
                        "time_window_seconds": 3,
                        "confidence": 0.88
                    }
                ],
                "noise_filtered": 8,
                "security_score": 35,
                "situation_summary": "Tu servidor esta siendo atacado. Alguien intenta adivinar la contrasena de tu panel de admin (500 intentos en 1 minuto). Tambien estan buscando archivos sensibles como tu .env."
            }
        elif role == AgentRole.REMEDIATION_ARCHITECT:
            return {
                "protocols": [
                    {
                        "protocol_id": "P001",
                        "title": "Bloquear IP atacante",
                        "urgency": "AHORA",
                        "plain_language": "Detectamos que la IP 45.33.49.12 intento entrar a tu panel 500 veces en 1 minuto. Es como si alguien probara 500 llaves en la cerradura de tu casa. Vamos a bloquearla.",
                        "technical_command": "sudo ufw deny from 45.33.49.12",
                        "estimated_fix_time": "30 segundos",
                        "risk_if_ignored": "Podrian adivinar tu contrasena y acceder a todos los datos de tus usuarios"
                    },
                    {
                        "protocol_id": "P002",
                        "title": "Activar RLS en Supabase",
                        "urgency": "AHORA",
                        "plain_language": "Tu base de datos esta completamente abierta. Es como dejar la puerta de tu negocio sin llave. Vamos a activar la proteccion.",
                        "technical_command": "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\nCREATE POLICY \"Users can only see own data\" ON users FOR SELECT USING (auth.uid() = id);",
                        "estimated_fix_time": "2 minutos",
                        "risk_if_ignored": "Cualquier persona puede ver TODOS los datos de TODOS tus usuarios"
                    }
                ],
                "overall_status": "EN_RIESGO",
                "telegram_message": "*VicoGuard AI - ALERTA DE SEGURIDAD*\n\nSecurity Score: *35/100* (EN RIESGO)\n\n*Ataque detectado:*\nAlguien intento entrar a tu panel 500 veces en 1 minuto desde la IP 45.33.49.12.\n\n*Acciones inmediatas:*\n1. Bloquear IP atacante (30 seg)\n2. Activar proteccion de base de datos (2 min)\n\nResponde 'APLICAR' para ejecutar las correcciones automaticamente."
            }
        return {"status": "mock", "role": role.value}


from datetime import datetime

if __name__ == "__main__":
    # Demo del equipo de agentes en modo mock
    team = SecurityTeamOrchestrator(llm_client=None)

    # Simular escaneo + logs
    from scripts.mock_server_logs import get_mock_logs

    mock_scan = {
        "target": "https://mi-app.supabase.co",
        "total_findings": 2,
        "critical_count": 1,
        "high_count": 1
    }

    result = team.run_full_pipeline(
        scan_results=mock_scan,
        server_logs=get_mock_logs()
    )

    print("\n" + "=" * 60)
    print("RESULTADO DEL PIPELINE MULTI-AGENTE")
    print("=" * 60)
    print(f"Agentes usados: {result['agents_used']}")
    print(f"Tiempo total: {result['total_pipeline_seconds']}s")
    print(f"\nMensaje de Telegram:")
    print(result['final_telegram_message'])
    print(f"\nEstado del equipo:")
    print(json.dumps(team.get_team_status(), indent=2))
