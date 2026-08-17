import os
import requests
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI()

def get_ai_response(message: str) -> str:
    api_url = "https://generativeai.googleapis.com/v1beta2/models/text-bison-001:generateText"
    api_key = os.getenv("GOOGLE_GENERATIVE_AI_API_KEY")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    payload = {
        "prompt": message,
        "max_tokens": 150
    }

    response = requests.post(api_url, headers=headers, json=payload)
    if response.status_code == 200:
        ai_response = response.json()
        return ai_response['choices'][0]['text'].strip()
    else:
        return f"[error] {response.status_code} - {response.text}"

@app.websocket("/chatwithAI")
async def chat_with_ai(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            # Send the received message to the AI model and get the response
            ai_response = get_ai_response(data)
            await websocket.send_text(ai_response)
    except WebSocketDisconnect:
        print("[info] client disconnected")