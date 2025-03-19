import base64
import json
import traceback
import os
import time
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests
import uvicorn
import secrets

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('logs', 'server.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("secure-ollama-server")

# Setup attestation log
attestation_log = logging.getLogger("attestation")
attestation_log.setLevel(logging.INFO)
attestation_handler = logging.FileHandler(os.path.join('logs', 'attestation.log'))
attestation_handler.setFormatter(logging.Formatter('%(asctime)s [ATTESTATION] %(message)s'))
attestation_log.addHandler(attestation_handler)

app = FastAPI(title="Secure Ollama Evaluation Server")

# Add CORS middleware with strict settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Can be restricted to specific client origins
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# Define key file paths
KEY_DIR = "server-keys"
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "server_private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "server_public_key.pem")

# Create keys directory if it doesn't exist
os.makedirs(KEY_DIR, exist_ok=True)

# Load evaluation dataset for verification
try:
    with open('eval_dataset.json', 'r') as f:
        EVALUATION_DATASET = json.load(f)
        logger.info(f"Loaded evaluation dataset with {len(EVALUATION_DATASET)} examples")
        
        # Create a hash of the dataset for attestation
        dataset_hash = hashlib.sha256(json.dumps(EVALUATION_DATASET, sort_keys=True).encode()).hexdigest()
        attestation_log.info(f"Evaluation dataset loaded with SHA256: {dataset_hash}")
except Exception as e:
    logger.error(f"Failed to load evaluation dataset: {e}")
    EVALUATION_DATASET = []

# Function to generate or load server's key pair
def get_server_keys():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        # Load existing keys
        logger.info("Loading existing server keys...")
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
        logger.info("Generating new server keys...")
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

# Calculate key fingerprint for attestation
key_fingerprint = hashlib.sha256(server_public_key_pem).hexdigest()
attestation_log.info(f"Server public key fingerprint: {key_fingerprint}")

# Ollama server configuration
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
attestation_log.info(f"Using Ollama API at: {OLLAMA_BASE_URL}")

class EncryptedRequest(BaseModel):
    encrypted_key: str
    encrypted_data: str
    iv: str
    client_public_key: str

class EncryptedResponse(BaseModel):
    encrypted_key: str
    encrypted_data: str
    iv: str
    attestation: str  # Added attestation field

# Dependency to rate limit requests
async def rate_limiter(request: Request):
    # Simple rate limiting could be implemented here
    return True

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
        logger.error(f"Decryption error: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
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
        logger.error(f"Encryption error: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Failed to encrypt data: {str(e)}")

def validate_prompt(prompt: str) -> bool:
    """Validate that the prompt is from the evaluation dataset"""
    if not EVALUATION_DATASET:
        # If dataset couldn't be loaded, allow all prompts
        return True
        
    return any(item.get('prompt') == prompt for item in EVALUATION_DATASET)

def call_ollama_api(prompt: str, model: str = "llama2", temperature: float = 0.7,
                   system_prompt: Optional[str] = None) -> Dict[str, Any]:
    """Call the Ollama API to generate a response"""
    url = f"{OLLAMA_BASE_URL}/api/generate"
    
    # Validate the prompt is from the evaluation dataset
    if not validate_prompt(prompt):
        attestation_log.warning(f"Attempted use of non-evaluation prompt: {prompt[:100]}...")
        raise HTTPException(status_code=403, detail="Prompt not found in evaluation dataset")
    
    # Create attestation log for this request
    request_id = hashlib.md5(f"{prompt}{time.time()}".encode()).hexdigest()
    attestation_log.info(f"Request[{request_id}] Model: {model}, Prompt: {prompt[:100]}...")
    
    payload = {
        "model": model,
        "prompt": prompt,
        "temperature": temperature,
        "stream": False
    }
    
    if system_prompt:
        payload["system"] = system_prompt
    
    try:
        logger.info(f"Calling Ollama API with model: {model}")
        
        # First, try to pull the model if it's not available
        try:
            # Check if model needs to be pulled
            check_model_url = f"{OLLAMA_BASE_URL}/api/tags"
            check_response = requests.get(check_model_url)
            check_response.raise_for_status()
            available_models = [m["name"] for m in check_response.json().get("models", [])]
            
            if model not in available_models:
                logger.info(f"Model {model} not available locally, attempting to pull...")
                pull_url = f"{OLLAMA_BASE_URL}/api/pull"
                pull_payload = {"name": model}
                pull_response = requests.post(pull_url, json=pull_payload)
                pull_response.raise_for_status()
                logger.info(f"Successfully pulled model: {model}")
        except Exception as pull_error:
            logger.warning(f"Error pulling model {model}: {str(pull_error)}")
            # Continue anyway, as the model might still work
        
        # Now try to generate with the model
        response = requests.post(url, json=payload)
        response.raise_for_status()
        result = response.json()
        
        # Hash the response for attestation
        response_hash = hashlib.md5(result.get("response", "").encode()).hexdigest()
        attestation_log.info(f"Request[{request_id}] completed with response hash: {response_hash}")
        
        # Add attestation info to be returned to the client
        result['attestation'] = {
            'request_id': request_id,
            'timestamp': time.time(),
            'prompt_hash': hashlib.md5(prompt.encode()).hexdigest(),
            'response_hash': response_hash,
            'server_fingerprint': key_fingerprint
        }
        
        return result
    except requests.exceptions.RequestException as e:
        logger.error(f"Ollama API error: {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            logger.error(f"Response text: {e.response.text}")
        
        attestation_log.error(f"Request[{request_id}] failed with error: {str(e)}")
        
        # If the model isn't available, return a fallback response
        if hasattr(e, 'response') and e.response and e.response.status_code == 404:
            fallback_response = {
                "response": f"The model '{model}' is not currently available. Please try another model.",
                "attestation": {
                    'request_id': request_id,
                    'timestamp': time.time(),
                    'prompt_hash': hashlib.md5(prompt.encode()).hexdigest(),
                    'response_hash': "fallback_response",
                    'server_fingerprint': key_fingerprint
                }
            }
            return fallback_response
            
        raise HTTPException(status_code=500, detail=f"Ollama API error: {str(e)}")

@app.get("/")
def read_root():
    return {"message": "Secure Ollama Evaluation Server is running"}

@app.get("/api/public-key")
def get_public_key():
    """Endpoint to retrieve the server's public key"""
    return {"public_key": server_public_key_pem.decode('utf-8')}

@app.get("/api/models", dependencies=[Depends(rate_limiter)])
def get_available_models():
    """Get available models from Ollama"""
    try:
        # Give Ollama some time to initialize and pull the model
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                response = requests.get(f"{OLLAMA_BASE_URL}/api/tags")
                response.raise_for_status()
                models = [model["name"] for model in response.json().get("models", [])]
                
                # If we found models, return them
                if models:
                    logger.info(f"Available models: {models}")
                    return {"models": models}
                    
                # If no models yet, retry after delay
                logger.info(f"No models found, retrying ({attempt+1}/{max_retries})...")
                time.sleep(retry_delay)
                
            except requests.exceptions.RequestException as e:
                logger.warning(f"Attempt {attempt+1}: Failed to get models: {str(e)}")
                time.sleep(retry_delay)
        
        # If we still don't have models after all retries, check if llama3.2 is there
        # This is just a fallback to ensure we always have at least one model
        logger.warning("Could not retrieve models list, defaulting to llama3.2")
        return {"models": ["llama3.2"]}
        
    except Exception as e:
        logger.error(f"Failed to get models after multiple attempts: {str(e)}")
        if hasattr(e, 'response') and e.response:
            logger.error(f"Response status: {e.response.status_code}")
            logger.error(f"Response text: {e.response.text}")
        
        # Default to llama3.2 as fallback
        return {"models": ["llama3.2"]}


@app.get("/api/attestation/verify/{request_id}")
def verify_attestation(request_id: str):
    """Verify an attestation log entry exists"""
    # This endpoint allows clients to verify that a request was properly logged
    attestation_file = os.path.join('logs', 'attestation.log')
    
    if not os.path.exists(attestation_file):
        raise HTTPException(status_code=404, detail="Attestation log not found")
    
    try:
        with open(attestation_file, 'r') as f:
            attestation_lines = f.readlines()
        
        matching_lines = [line for line in attestation_lines if request_id in line]
        
        if matching_lines:
            return {
                "verified": True,
                "log_entries": matching_lines
            }
        else:
            return {
                "verified": False,
                "message": "No attestation record found for this request ID"
            }
    except Exception as e:
        logger.error(f"Error verifying attestation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error verifying attestation: {str(e)}")

@app.post("/api/secure-generate", dependencies=[Depends(rate_limiter)])
async def secure_generate(request: EncryptedRequest):
    """
    Securely generate a response from Ollama using hybrid encryption
    
    1. Decrypt the client's request using hybrid RSA+AES decryption
    2. Call Ollama API with the decrypted request
    3. Encrypt the response using hybrid RSA+AES encryption
    4. Return the encrypted response
    """
    try:
        logger.info("Received secure generate request")
        
        # Decrypt the request data
        logger.info("Decrypting request data...")
        decrypted_data = hybrid_decrypt(
            request.encrypted_key, 
            request.encrypted_data, 
            request.iv, 
            server_private_key
        )
        
        # Extract parameters for Ollama
        prompt = decrypted_data.get("prompt")
        model = decrypted_data.get("model", "llama2")
        temperature = decrypted_data.get("temperature", 0.7)
        system_prompt = decrypted_data.get("system_prompt")
        
        if not prompt:
            raise HTTPException(status_code=400, detail="Prompt is required")
        
        # Call Ollama API
        logger.info(f"Calling Ollama API with model: {model}")
        ollama_response = call_ollama_api(prompt, model, temperature, system_prompt)
        
        # Create an attestation hash that the client can verify
        attestation_signature = {
            'request_id': ollama_response['attestation']['request_id'],
            'timestamp': ollama_response['attestation']['timestamp'],
            'fingerprint': key_fingerprint
        }
        
        # Sign the attestation
        signature_data = json.dumps(attestation_signature, sort_keys=True).encode()
        signature = base64.b64encode(
            server_private_key.sign(
                signature_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        ).decode('utf-8')
        
        ollama_response['attestation']['signature'] = signature
        
        # Encrypt the response using client's public key
        logger.info("Encrypting response...")
        encrypted_key, encrypted_data, iv = hybrid_encrypt(ollama_response, request.client_public_key)
        logger.info("Response encrypted successfully")
        
        return {
            "encrypted_key": encrypted_key,
            "encrypted_data": encrypted_data,
            "iv": iv,
            "attestation": {
                "request_id": ollama_response['attestation']['request_id'],
                "fingerprint": key_fingerprint
            }
        }
    except Exception as e:
        logger.error(f"Error in secure_generate: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Error in secure generation: {str(e)}")

if __name__ == "__main__":
    # Log startup for attestation
    attestation_log.info(f"=== Secure Ollama Server Starting ===")
    attestation_log.info(f"Server version: 1.0.0")
    attestation_log.info(f"Ollama API endpoint: {OLLAMA_BASE_URL}")
    
    # Start the server
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)