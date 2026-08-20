import os
from wsgiref import headers
from groq import Groq
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from dotenv import load_dotenv

load_dotenv() 
app = FastAPI()

class AIRequest(BaseModel):
    message: str
    action: Optional[str] = None
    selected_function: Optional[dict] = None
    metadata: Optional[dict] = None

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

def get_ai_response(message: str) -> str:
    KEY = os.getenv("GENERATIVE_AI_KEY")

    client = Groq(api_key=KEY)

    completion = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[
            {
                "role": "user",
                "content": message
            }
        ],
        temperature=1,
        max_completion_tokens=2048,
        top_p=1,
        reasoning_effort="medium",
        stream=True,
        stop=None
    )

    result = ""

    for chunk in completion:
        content = chunk.choices[0].delta.content

        if content:
            print(content, end="", flush=True)
            result += content

    return result

@app.post("/chatwithAI")
async def chat_with_ai(request: AIRequest):
    context = [f"User request: {request.message}"]
    if request.action:
        context.append(f"Action: {request.action}")
    if request.selected_function:
        context.append(f"Selected function: {request.selected_function}")
    if request.metadata:
        context.append(f"Parsed PE metadata: {request.metadata}")

    return get_ai_response("\n".join(context))