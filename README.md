# Secure Ollama Execution Environment

This project implements a secure execution environment for running Ollama model evaluations inside Docker with strong security guarantees and attestation capabilities.

## Security Guarantees

The environment provides the following security guarantees:

1. **Isolated Execution**: The Docker containers run in a restricted environment with limited system access.
2. **Prompt Validation**: Only prompts from the predefined evaluation dataset can be processed.
3. **No Exfiltration**: The containers are configured to prevent data exfiltration.
4. **Secure Communication**: All communication is encrypted using hybrid RSA+AES encryption.
5. **Attestation**: Each request and response is logged and can be cryptographically verified.
6. **Minimal Environment**: The containers run with minimal dependencies and capabilities.

## Components

- `Dockerfile`: Defines a minimal container with only necessary components
- `docker-compose.yml`: Orchestrates the Ollama and evaluation server containers
- `seccomp-profile.json`: Restricts system calls for enhanced security
- `server.py`: Modified server with attestation capabilities
- `client.py`: Client with verification extensions
- `eval_dataset.json`: Dataset for evaluation

## Setup Instructions

1. Ensure Docker and Docker Compose are installed
2. Clone this repository
3. Make the startup script executable:
   ```
   chmod +x run-secure-environment.sh
   ```
4. Run the startup script:
   ```
   ./run-secure-environment.sh
   ```

## Verification & Attestation

The system provides two levels of attestation:

1. **Cryptographic Attestation**: Each response includes a signed attestation that can be verified.
2. **Log Verification**: All requests are logged and can be verified against the server logs.

### How Attestation Works

1. When the server processes a request, it:
   - Validates the prompt against the evaluation dataset
   - Logs the request details
   - Creates a cryptographic signature
   - Returns the attestation with the response

2. The client can verify:
   - The signature using the server's public key
   - The log entry via the attestation verification endpoint

### Verification Code

```python
# Example verification
from client_extension import AttestationVerifier

# Initialize verifier
verifier = AttestationVerifier("http://localhost:8000")

# Perform verification of a response
result = verifier.full_verification(response)

if result['verified']:
    print("Response is verified and attested!")
else:
    print(f"Verification failed: {result['reason']}")
```

## Security Measures

### Container Security

- **Read-only filesystem**: Prevents modification of container contents
- **No privilege escalation**: Prevents gaining additional privileges
- **Seccomp profile**: Restricts system calls to minimum required
- **Resource limits**: Prevents resource exhaustion
- **Non-root user**: Runs processes as non-privileged user

### Network Security

- **Isolated network**: Custom bridge network for containers
- **No external network access**: Ollama container not exposed to host
- **Encrypted communication**: All API calls use hybrid encryption

### Execution Security

- **Prompt validation**: Ensures only evaluation dataset prompts are processed
- **Request logging**: All requests are logged with cryptographic attestations
- **No additional processes**: Cannot spawn additional processes

## Extending the Environment

To add additional security measures:

1. **Trusted Platform Module (TPM)**: For hardware-based attestation
2. **Intel SGX**: For confidential computing with memory encryption
3. **Formal verification**: Prove security properties of the environment

## Troubleshooting

If you encounter issues:

1. Check logs: `docker-compose logs`
2. Verify container status: `docker-compose ps`
3. Check attestation logs: `cat logs/attestation.log`