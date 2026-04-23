from fastapi import WebSocket
from typing import List
import json
from datetime import datetime

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        # Immediately send a connection success payload
        await self.send_personal_message({"type": "connect", "message": "Terminal connection established."}, websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        message["timestamp"] = datetime.now().strftime("%H:%M:%S")
        await websocket.send_text(json.dumps(message))

    async def broadcast(self, message: dict):
        message["timestamp"] = datetime.now().strftime("%H:%M:%S")
        payload = json.dumps(message)
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception as e:
                pass

manager = ConnectionManager()
