import base64
import json
import traceback
import os
from typing import Dict, Any, Optional, Tuple
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests
import uvicorn
import secrets

app = FastAPI(title="Secure Ollama Evaluation Server")

# Define key file paths
KEY_DIR = "server-keys"
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "server_private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "server_public_key.pem")

# Create keys directory if it doesn't exist
os.makedirs(KEY_DIR, exist_ok=True)

# Function to generate or load server's key pair
def get_server_keys():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        # Load existing keys
        print("Loading existing server keys...")
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key_data = f.read()
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )
        
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key_pem = f.read()
    else:
        # Generate new keys
        print("Generating new server keys...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Save private key
        private_key_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key_data)
        
        # Save public key
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key_pem)
    
    return private_key, public_key_pem

# Get or generate server keys
server_private_key, server_public_key_pem = get_server_keys()

# Ollama server configuration
OLLAMA_BASE_URL = "http://localhost:11434"

class EncryptedRequest(BaseModel):
    encrypted_key: str
    encrypted_data: str
    iv: str
    client_public_key: str

class EncryptedResponse(BaseModel):
    encrypted_key: str
    encrypted_data: str
    iv: str

def hybrid_decrypt(encrypted_key: str, encrypted_data: str, iv: str, private_key: rsa.RSAPrivateKey) -> Dict[str, Any]:
    """
    Decrypt data using hybrid RSA+AES encryption
    
    1. Decrypt the AES key using RSA private key
    2. Use the AES key to decrypt the data
    """
    try:
        # Decode base64 encrypted key and data
        encrypted_key_bytes = base64.b64decode(encrypted_key)
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        iv_bytes = base64.b64decode(iv)
        
        # Decrypt the AES key using RSA
        aes_key = private_key.decrypt(
            encrypted_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt the data using AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv_bytes),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data_bytes) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_length = padded_data[-1]
        data = padded_data[:-padding_length]
        
        # Parse the JSON data
        return json.loads(data.decode('utf-8'))
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=400, detail=f"Failed to decrypt data: {str(e)}")

def hybrid_encrypt(data: Dict[str, Any], public_key_pem: str) -> Tuple[str, str, str]:
    """
    Encrypt data using hybrid RSA+AES encryption
    
    1. Generate a random AES key
    2. Encrypt the data using AES
    3. Encrypt the AES key using RSA
    """
    try:
        # Load the client's public key
        client_public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # Generate a random AES key (256 bits = 32 bytes)
        aes_key = secrets.token_bytes(32)
        
        # Generate a random IV (Initialization Vector)
        iv = secrets.token_bytes(16)  # AES block size is 16 bytes
        
        # Convert data to JSON string and encode
        data_bytes = json.dumps(data).encode('utf-8')
        
        # Add PKCS7 padding
        block_size = 16  # AES block size
        padding_length = block_size - (len(data_bytes) % block_size)
        padded_data = data_bytes + bytes([padding_length] * padding_length)
        
        # Encrypt the data using AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data_bytes = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt the AES key using RSA
        encrypted_key_bytes = client_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Encode as base64 for transmission
        encrypted_key = base64.b64encode(encrypted_key_bytes).decode('utf-8')
        encrypted_data = base64.b64encode(encrypted_data_bytes).decode('utf-8')
        iv_base64 = base64.b64encode(iv).decode('utf-8')
        
        return encrypted_key, encrypted_data, iv_base64
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Failed to encrypt data: {str(e)}")

def call_ollama_api(prompt: str, model: str = "llama2", temperature: float = 0.7,
                   system_prompt: Optional[str] = None) -> Dict[str, Any]:
    """Call the Ollama API to generate a response"""
    url = f"{OLLAMA_BASE_URL}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "temperature": temperature,
        "stream": False
    }
    
    if system_prompt:
        payload["system"] = system_prompt
    
    try:
        print(f"Calling Ollama API with payload: {payload}")
        response = requests.post(url, json=payload)
        response.raise_for_status()
        result = response.json()
        print(f"Ollama API response received: {result}")
        return result
    except requests.exceptions.RequestException as e:
        print(f"Ollama API error: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print(f"Response text: {e.response.text}")
        raise HTTPException(status_code=500, detail=f"Ollama API error: {str(e)}")

@app.get("/")
def read_root():
    return {"message": "Secure Ollama Evaluation Server is running"}

@app.get("/api/public-key")
def get_public_key():
    """Endpoint to retrieve the server's public key"""
    return {"public_key": server_public_key_pem.decode('utf-8')}

@app.get("/api/models")
def get_available_models():
    """Get available models from Ollama"""
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags")
        response.raise_for_status()
        models = [model["name"] for model in response.json().get("models", [])]
        return {"models": models}
    except requests.exceptions.RequestException as e:
        print(f"Failed to get models: {str(e)}")
        if hasattr(e, 'response') and e.response:
            print(f"Response status: {e.response.status_code}")
            print(f"Response text: {e.response.text}")
        raise HTTPException(status_code=500, detail=f"Failed to get models: {str(e)}")

@app.post("/api/secure-generate")
async def secure_generate(request: EncryptedRequest):
    """
    Securely generate a response from Ollama using hybrid encryption
    
    1. Decrypt the client's request using hybrid RSA+AES decryption
    2. Call Ollama API with the decrypted request
    3. Encrypt the response using hybrid RSA+AES encryption
    4. Return the encrypted response
    """
    try:
        print("Received secure generate request")
        
        # Decrypt the request data
        print("Decrypting request data...")
        decrypted_data = hybrid_decrypt(
            request.encrypted_key, 
            request.encrypted_data, 
            request.iv, 
            server_private_key
        )
        print(f"Decrypted data: {decrypted_data}")
        
        # Extract parameters for Ollama
        prompt = decrypted_data.get("prompt")
        model = decrypted_data.get("model", "llama2")
        temperature = decrypted_data.get("temperature", 0.7)
        system_prompt = decrypted_data.get("system_prompt")
        
        if not prompt:
            raise HTTPException(status_code=400, detail="Prompt is required")
        
        # Call Ollama API
        print(f"Calling Ollama API with model: {model}, prompt: {prompt}")
        ollama_response = call_ollama_api(prompt, model, temperature, system_prompt)
        
        # Encrypt the response using client's public key
        print("Encrypting response...")
        encrypted_key, encrypted_data, iv = hybrid_encrypt(ollama_response, request.client_public_key)
        print("Response encrypted successfully")
        
        return {
            "encrypted_key": encrypted_key,
            "encrypted_data": encrypted_data,
            "iv": iv
        }
    except Exception as e:
        print(f"Error in secure_generate: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Error in secure generation: {str(e)}")

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True) 