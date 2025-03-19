#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Secure Ollama Evaluation Environment${NC}"

# Create the necessary directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p logs

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Docker Compose is not installed. Please install Docker Compose first.${NC}"
    exit 1
fi

# Verify the environment files exist
if [ ! -f "server.py" ] || [ ! -f "eval_dataset.json" ] || [ ! -f "requirements.txt" ]; then
    echo -e "${RED}Required files are missing. Please ensure server.py, eval_dataset.json, and requirements.txt exist.${NC}"
    exit 1
fi

# Verify Docker Compose file exists
if [ ! -f "docker-compose.yml" ]; then
    echo -e "${RED}docker-compose.yml is missing. Please create it first.${NC}"
    exit 1
fi

# Check for seccomp profile
if [ ! -f "seccomp-profile.json" ]; then
    echo -e "${RED}seccomp-profile.json is missing. Please create it first.${NC}"
    exit 1
fi

# Start the containers
echo -e "${YELLOW}Starting containers...${NC}"
docker-compose up -d

# Wait for services to start
echo -e "${YELLOW}Waiting for services to start...${NC}"
sleep 5

# Check if the containers are running
if docker-compose ps | grep -q "eval-server.*Up"; then
    echo -e "${GREEN}Evaluation server is running!${NC}"
else
    echo -e "${RED}Evaluation server failed to start. Check logs with 'docker-compose logs eval-server'${NC}"
    exit 1
fi

if docker-compose ps | grep -q "ollama-service.*Up"; then
    echo -e "${GREEN}Ollama service is running!${NC}"
else
    echo -e "${RED}Ollama service failed to start. Check logs with 'docker-compose logs ollama'${NC}"
    exit 1
fi

# Show the public endpoint
echo -e "${GREEN}Secure Ollama Evaluation Environment is ready!${NC}"
echo -e "API is available at: http://localhost:8000"
echo -e "To run evaluations, use the client.py script"
echo -e "To view logs: docker-compose logs -f"
echo -e "To stop the environment: docker-compose down"

# Print attestation information
echo -e "\n${YELLOW}Attestation Information${NC}"
echo -e "Attestation logs are available in: ./logs/attestation.log"
echo -e "Server logs are available in: ./logs/server.log"
echo -e "\n${GREEN}Use the AttestationVerifier class to verify responses from the server${NC}"

exit 0
