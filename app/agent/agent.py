import requests


OLLAMA_URL = "http://localhost:11434/api/chat"

MODEL = "qwen3:4b-instruct"


SYSTEM_PROMPT = """
You are Raphael's test AI agent.

You are a helpful assistant.

You have access to several tools, but during this
initial phase you are only being tested for LLM
communication.

Do not invent tool results.
"""


def ask_llm(user_input: str):

    response = requests.post(

        OLLAMA_URL,

        json={

            "model": MODEL,

            "messages": [

                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },

                {
                    "role": "user",
                    "content": user_input
                }
            ],

            "stream": False
        },

        timeout=120
    )

    response.raise_for_status()

    data = response.json()

    return data["message"]["content"]


def run_agent(user_input: str):

    response = ask_llm(user_input)

    return {

        "user_input": user_input,

        "response": response
    }