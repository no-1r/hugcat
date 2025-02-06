from fastapi import FastAPI, WebSocket

sessions = { } 

app = FastAPI()

@app.websocket("/ws")




async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()

    message = await websocket.receive_text()


   

    if message.startswith("player_id:"):
        player_id = message.split(":")[1]
        print(f"Player connected with ID: {player_id}")
        sessions[player_id] = {"ready": False, "websocket": websocket}


    if message == "ready":
        print("player clicked")
        sessions[player_id]["ready"] = True

    player_count = 0
    
    for player_id in sessions: 
       
        if sessions[player_id]["ready"]:
            player_count += 1
        
        if player_count == 2: 
            
        
            for player_id in sessions:
                if sessions[player_id]["ready"] == True: 
                    await sessions[player_id]["websocket"].send_text("hug")



