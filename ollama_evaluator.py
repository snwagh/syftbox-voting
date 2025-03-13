import requests
import pandas as pd
from typing import List, Dict, Any
import time

class OllamaEvaluator:
    """
    Simple evaluator for local Ollama models
    """
    def __init__(self, base_url: str = "http://localhost:11434"):
        """Initialize with Ollama server URL"""
        self.base_url = base_url
        # Check if Ollama is running
        try:
            response = requests.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                self.available_models = [model["name"] for model in response.json()["models"]]
                print(f"Connected to Ollama. Available models: {self.available_models}")
            else:
                print("Ollama server responded with an error. Make sure it's running correctly.")
        except requests.exceptions.ConnectionError:
            print("Could not connect to Ollama server. Make sure it's running on the specified URL.")
            self.available_models = []

    def generate(self, prompt: str, model: str = "llama2", temperature: float = 0.7) -> Dict[str, Any]:
        """Generate a response from the model"""
        if model not in self.available_models:
            print(f"Warning: Model '{model}' not found in available models. Will attempt anyway.")
        
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "temperature": temperature,
            "stream": False
        }
        
        start_time = time.time()
        response = requests.post(url, json=payload)
        end_time = time.time()
        
        if response.status_code == 200:
            result = response.json()
            result['latency'] = end_time - start_time
            return result
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            return {"error": response.text}

    def evaluate_dataset(self, dataset: List[Dict[str, str]], model: str = "llama2") -> pd.DataFrame:
        """
        Evaluate a model on a dataset of prompts and expected responses
        
        dataset: List of dictionaries with keys 'prompt' and 'expected_response'
        model: Name of the model to evaluate
        
        Returns: DataFrame with evaluation results
        """
        results = []
        
        for i, example in enumerate(dataset):
            prompt = example['prompt']
            expected = example.get('expected_response', None)
            
            print(f"Evaluating example {i+1}/{len(dataset)}...")
            response = self.generate(prompt, model)
            
            result = {
                'prompt': prompt,
                'model_response': response.get('response', ''),
                'expected_response': expected,
                'latency': response.get('latency', 0),
                'eval_score': None
            }
            
            # Simple exact match evaluation if expected response exists
            if expected is not None:
                result['eval_score'] = 1.0 if expected.strip() == response.get('response', '').strip() else 0.0
            
            results.append(result)
        
        return pd.DataFrame(results)

    def compare_models(self, prompt: str, models: List[str], temperature: float = 0.7) -> pd.DataFrame:
        """Compare multiple models on the same prompt"""
        results = []
        
        for model in models:
            if model not in self.available_models:
                print(f"Warning: Model '{model}' not found in available models. Skipping.")
                continue
                
            print(f"Testing model: {model}")
            response = self.generate(prompt, model, temperature)
            
            results.append({
                'model': model,
                'response': response.get('response', ''),
                'latency': response.get('latency', 0)
            })
        
        return pd.DataFrame(results)


# Example usage
if __name__ == "__main__":
    # Initialize the evaluator
    evaluator = OllamaEvaluator()
    
    # Example 1: Simple generation
    prompt = "Explain the concept of LLM evaluation in one paragraph."
    result = evaluator.generate(prompt)
    print("\nSingle Generation Example:")
    print(f"Prompt: {prompt}")
    print(f"Response: {result.get('response', '')}")
    print(f"Latency: {result.get('latency', 0):.2f} seconds")
    
    # Example 2: Evaluate on a small dataset
    print("\nDataset Evaluation Example:")
    test_dataset = [
        {
            'prompt': 'What is the capital of France?',
            'expected_response': 'The capital of France is Paris.'
        },
        {
            'prompt': 'Write a function in Python to calculate the factorial of a number.',
            'expected_response': None  # No exact expected response
        },
        {
            'prompt': 'Explain what machine learning is in one sentence.',
            'expected_response': None
        }
    ]
    
    # Check if we have at least one model available
    if evaluator.available_models:
        default_model = evaluator.available_models[0]
        eval_results = evaluator.evaluate_dataset(test_dataset, model=default_model)
        print(eval_results[['prompt', 'model_response', 'latency']])
        
        # Example 3: Compare models if multiple are available
        if len(evaluator.available_models) > 1:
            print("\nModel Comparison Example:")
            comparison_prompt = "Explain the advantages and disadvantages of transformer models."
            model_comparison = evaluator.compare_models(
                comparison_prompt, 
                evaluator.available_models[:2]  # Compare first two models
            )
            print(model_comparison[['model', 'latency']])
            print("\nSample responses from different models:")
            for i, row in model_comparison.iterrows():
                print(f"\n{row['model']}:")
                print(row['response'][:200] + "..." if len(row['response']) > 200 else row['response'])