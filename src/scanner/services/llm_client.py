"""
VicoGuard AI — LLM Client Adapter
===================================
Adaptador que conecta el SecurityTeamOrchestrator con OpenAI/Gemini.
Implementa la interfaz .chat() que los agentes esperan.

Uso:
    from scanner.services.llm_client import OpenAILLMClient
    client = OpenAILLMClient()
    team = SecurityTeamOrchestrator(llm_client=client)
"""
import os
import json
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("vicoguard.llm")


class OpenAILLMClient:
    """
    Adaptador LLM que envuelve la API de OpenAI para usarla
    con el SecurityTeamOrchestrator.
    
    Implementa el contrato: .chat(system_prompt, user_message, temperature, max_tokens) -> str
    """

    def __init__(self, model: str = None, api_key: str = None, base_url: str = None):
        """
        Args:
            model: nombre del modelo a usar (default depende del proveedor detectado).
            api_key: API key explicita. Si no viene, cae a OPENAI_API_KEY/env.
            base_url: endpoint OpenAI-compatible custom (ej: GLM Coding Plan de Z.ai).
                Si viene, tiene prioridad sobre la deteccion automatica Gemini/OpenAI
                y se usa tal cual con la api_key resuelta.
        """
        from openai import OpenAI

        openai_key = api_key or os.getenv("OPENAI_API_KEY")
        gemini_key = os.getenv("GEMINI_API_KEY")

        if base_url:
            self.model = model or "gpt-4o"
            self.client = OpenAI(api_key=openai_key, base_url=base_url)
            logger.info(f"[LLM] Inicializado adaptador custom (base_url={base_url}, model={self.model})")
        elif gemini_key:
            self.model = model or "gemini-1.5-flash"
            self.client = OpenAI(
                api_key=gemini_key,
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
            )
            logger.info(f"[LLM] Inicializado adaptador Gemini ({self.model})")
        else:
            self.model = model or "gpt-4o"
            self.client = OpenAI(api_key=openai_key)
            logger.info(f"[LLM] Inicializado adaptador OpenAI ({self.model})")
        
        self._total_tokens = 0
        self._total_calls = 0

    def chat(
        self,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.3,
        max_tokens: int = 1024,
    ) -> str:
        """
        Envía un mensaje al LLM y devuelve la respuesta como string JSON.
        Compatible con la interfaz que espera agent_team.py.
        """
        logger.info(f"[LLM] Llamando {self.model} (temp={temperature}, max_tokens={max_tokens})")

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
            )

            result = response.choices[0].message.content
            tokens_used = response.usage.total_tokens if response.usage else 0
            self._total_tokens += tokens_used
            self._total_calls += 1

            logger.info(f"[LLM] Respuesta recibida ({tokens_used} tokens, total acumulado: {self._total_tokens})")
            return result

        except Exception as e:
            logger.error(f"[LLM] Error en llamada: {e}")
            raise

    @property
    def stats(self) -> dict:
        """Devuelve estadísticas de uso del LLM."""
        return {
            "model": self.model,
            "total_calls": self._total_calls,
            "total_tokens": self._total_tokens,
            "estimated_cost_usd": round(self._total_tokens * 0.00001, 4),
        }


# --- Testing directo ---
if __name__ == "__main__":
    print("🧪 Probando LLM Client...")
    client = OpenAILLMClient()
    result = client.chat(
        system_prompt="Eres un asistente que responde en JSON. Siempre devuelve {\"status\": \"ok\", \"message\": \"...\"}",
        user_message="Di hola en español",
        temperature=0.5,
        max_tokens=100,
    )
    print(f"Respuesta: {result}")
    print(f"Stats: {client.stats}")
