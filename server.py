from fastapi import FastAPI, WebSocket
import uvicorn

sessions = { } 

app = FastAPI()





@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()

    

    while True: 
            message = await websocket.receive_text()
    
            player_count = 0

            if message.startswith("player_id:"):
                player_id = message.split(":")[1]
                print(f"Player connected with ID: {player_id}")
                sessions[player_id] = {"ready": False, "websocket": websocket}


            if message == "ready":
                print("player clicked")
                sessions[player_id]["ready"] = True

                
            
            for player_id in sessions: 
            
                if sessions[player_id]["ready"]:
                    player_count += 1
                
            if player_count == 2: 
                    
                
                for player_id in sessions:
                    if sessions[player_id]["ready"] == True: 
                        await sessions[player_id]["websocket"].send_text("hug")

if __name__ == "__main__":
    print("Starting server...")  # Debugging print
    uvicorn.run(app, host="0.0.0.0", port=8000)


