"""One ASGI app hosting every fixture server + control + mock exfil sink. Run: uvicorn fixtures.servers.host:app --port 9000"""
from fastapi import FastAPI

from . import benign_server, exfil, invisible_server, poisoned_server, rug_pull_server, shadow_server

app = FastAPI(title="Filigree fixture servers (mock, local only)")
for m in (benign_server, invisible_server, poisoned_server, rug_pull_server, shadow_server):
    app.include_router(m.router)

# Server ids are host-assigned (D-14): name on the left is the Filigree-side id.
SERVERS = {"srv-benign": "benign", "srv-poisoned": "poisoned", "srv-invisible": "invisible",
           "srv-rugpull": "rugpull", "srv-shadow": "shadow"}


@app.post("/control/reset")
def reset():
    rug_pull_server.reset(); exfil.reset(); return {"ok": True}


@app.post("/control/rug_pull/{mode}")
def mutate(mode: str):
    rug_pull_server.mutate(mode); return {"mode": mode}


@app.get("/exfil/log")
def exfil_log(): return exfil.LOG
