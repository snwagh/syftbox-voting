# Secure Ollama Evaluation System

This project implements a secure evaluation system for Ollama models using encrypted communication between client and server.

## Architecture

The system consists of the following components:

1. **FastAPI Server**: Wraps the Ollama server and handles encrypted requests
2. **Client**: Handles encryption, communication with the server, evaluation, and visualization

## Security Features

- **Public Key Encryption**: All communication between client and server is encrypted
- **Client-Side Encryption**: Evaluation data is encrypted with the server's public key
- **Server-Side Encryption**: Responses are encrypted with the client's public key
- **Secure Key Exchange**: Public keys are exchanged during initialization

## Installation

1. Clone the repository
2. Install dependencies:

```bash
uv pip install -r requirements.txt
```

3. Ensure Ollama is installed and running on your system

## Usage

### Starting the Server

1. Start the Ollama server (default port: 11434)
2. Start the secure FastAPI server:

```bash
uv run python server.py
```

The server will run on http://localhost:8000 by default.

### Running Evaluations

Run the secure evaluation pipeline:

```bash
uv run python client.py
```

Follow the interactive prompts to:
1. Enter the server URL
2. Select models to evaluate
3. Choose evaluation mode (quick test, full evaluation, or custom subset)

### Evaluation Results

Results will be saved to the `output` directory:
- `secure_evaluation_summary.csv`: Summary metrics for each model
- `secure_evaluation_details.csv`: Detailed results for each example
- Visualization images:
  - `secure_model_performance.png`
  - `secure_model_latency.png`
  - `secure_metrics_breakdown.png`

## Components

### server.py

FastAPI server that:
- Generates server key pair
- Provides endpoint to share public key
- Receives encrypted requests
- Decrypts requests using server's private key
- Calls Ollama API
- Encrypts responses using client's public key

### client.py

Consolidated client module that:
- Generates client key pair
- Fetches server's public key
- Encrypts requests using server's public key
- Sends encrypted requests to server
- Decrypts responses using client's private key
- Implements evaluation metrics
- Handles dataset loading and model selection
- Generates visualizations and saves results

## Evaluation Metrics

The system evaluates models using the following metrics:
- Semantic Similarity
- Factual Accuracy
- Keyword Presence
- Answer Relevance
- Content Safety
- Overall Score (weighted average of all metrics)

## Security Considerations

- This implementation uses RSA encryption which has size limitations for encrypted data
- For production use, consider implementing hybrid encryption (RSA + AES)
- Keys are generated at runtime and not persisted - consider key management for production
- The server's private key is kept in memory - consider secure key storage for production