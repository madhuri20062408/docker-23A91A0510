import os
from fastapi import FastAPI, HTTPException
from app.crypto_utils import decrypt_seed
from app.totp_utils import generate_totp_code, verify_totp_code, current_code_and_remaining

app = FastAPI()

DATA_DIR = os.getenv("DATA_DIR", "/data")
PRIVATE_KEY_PATH = "/srv/app/student_private.pem"

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(body: dict):
    try:
        encrypted_seed_b64 = body.get("encrypted_seed", "").strip()
        if not encrypted_seed_b64:
            raise ValueError("encrypted_seed is required")
        
        seed = decrypt_seed(encrypted_seed_b64, PRIVATE_KEY_PATH)
        seed_file = os.path.join(DATA_DIR, "seed.txt")
        os.makedirs(DATA_DIR, exist_ok=True)
        
        with open(seed_file, "w") as f:
            f.write(seed)
        
        return {"status": "ok"}
    except Exception as e:
        print(f"ERROR in /decrypt-seed: {e}")
        raise HTTPException(status_code=500, detail="Decryption failed")

@app.get("/generate-2fa")
def generate_2fa():
    try:
        seed_file = os.path.join(DATA_DIR, "seed.txt")
        if not os.path.isfile(seed_file):
            raise FileNotFoundError("Seed not decrypted yet")
        
        with open(seed_file, "r") as f:
            seed = f.read().strip()
        
        code, remaining = current_code_and_remaining(seed)
        return {"code": code, "valid_for": remaining}
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    except Exception as e:
        print(f"ERROR: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-2fa")
def verify_2fa(body: dict):
    try:
        code = body.get("code", "").strip()
        if not code:
            raise HTTPException(status_code=400, detail="Missing code")
        
        seed_file = os.path.join(DATA_DIR, "seed.txt")
        if not os.path.isfile(seed_file):
            raise HTTPException(status_code=500, detail="Seed not decrypted yet")
        
        with open(seed_file, "r") as f:
            seed = f.read().strip()
        
        is_valid = verify_totp_code(seed, code, valid_window=1)
        return {"valid": is_valid}
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR: {e}")
        raise HTTPException(status_code=500, detail=str(e))
