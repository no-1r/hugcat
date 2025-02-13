from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn
import time
import os

# Ensure we get the full path
static_dir = os.path.abspath("static")
print(f"Serving static files from: {static_dir}")

app = FastAPI()
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Serve the index.html file when accessing the root
from fastapi.responses import FileResponse

@app.get("/")
async def serve_homepage():
    return FileResponse(os.path.join(static_dir, "index.html"))




app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",  #  (Change this)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
    expose_headers=["*"]
)



sessions = {}  # Stores player statuses
hug_active = False
hug_start_time = 0



@app.post("/ready/{player_id}")
async def player_ready(player_id: str):
    if player_id not in sessions: 
        sessions[player_id] = {"ready": False, "active": True}
    sessions[player_id]["ready"] = True 
    return{"message": "player is ready"}


@app.get("/status")
async def check_status():
    global hug_active, hug_start_time
    try:

        ready_players = [player for player in sessions if sessions[player]["ready"]]
        if hug_active:
            if time.time() - hug_start_time < 3:
                return{"status": "hug"}
            else: 
                hug_active = False
        
        if len(ready_players) >= 2:
            print("sending hugs!!")
            hug_active = True 
            hug_start_time = time.time()

            
            for player in sessions:
                sessions[player]["ready"] = False
            
            return {"status": "hug"}
        hug_active = False
            

            

        return {"status": "waiting"}
    except Exception as e: 
        print(f"error in /status: {e}")
        return{"status": "error", "message": str(e)}
    
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))  # Railway assigns PORT dynamically
    uvicorn.run(app, host="0.0.0.0", port=port)