from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  #  (Change this)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)



sessions = {}  # Stores player statuses

@app.post("/ready/{player_id}")
async def player_ready(player_id: str):
    """ Mark a player as ready """
    sessions[player_id] = True
    return {"message": "Player is ready"}

@app.get("/status")
async def check_status():
    """ Check if both players are ready """
    if sum(sessions.values()) >= 2:
        return {"status": "hug"}  # Send hug signal
    return {"status": "waiting"}  # Still waiting for the other player

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)