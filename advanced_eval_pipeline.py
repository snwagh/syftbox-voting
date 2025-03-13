import requests
import json
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Callable
import time
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class AdvancedOllamaEvaluator:
    """
    Advanced evaluator for local Ollama models with custom metrics
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

    def generate(self, prompt: str, model: str = "llama2", temperature: float = 0.7,
                 system_prompt: str = None) -> Dict[str, Any]:
        """Generate a response from the model with optional system prompt"""
        if model not in self.available_models:
            print(f"Warning: Model '{model}' not found in available models. Will attempt anyway.")
        
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "temperature": temperature,
            "stream": False
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
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

    def semantic_similarity(self, text1: str, text2: str) -> float:
        """Calculate semantic similarity between two texts using TF-IDF and cosine similarity"""
        vectorizer = TfidfVectorizer().fit_transform([text1, text2])
        vectors = vectorizer.toarray()
        return cosine_similarity([vectors[0]], [vectors[1]])[0][0]

    def factual_accuracy(self, response: str, facts: List[str]) -> float:
        """
        Measure factual accuracy by checking if key facts are present in the response
        Returns a score between 0 and 1
        """
        score = 0
        for fact in facts:
            if fact.lower() in response.lower():
                score += 1
        return score / len(facts) if facts else 0

    def keyword_presence(self, response: str, keywords: List[str]) -> float:
        """Check what percentage of required keywords are present in the response"""
        if not keywords:
            return 1.0
            
        present = 0
        for keyword in keywords:
            if keyword.lower() in response.lower():
                present += 1
        return present / len(keywords)

    def answer_relevance(self, prompt: str, response: str) -> float:
        """Estimate how relevant the response is to the prompt using semantic similarity"""
        return self.semantic_similarity(prompt, response)

    def content_safety(self, response: str, unsafe_patterns: List[str] = None) -> float:
        """
        Check if response contains potentially unsafe content
        Higher score means safer content (1.0 = completely safe)
        """
        if unsafe_patterns is None:
            unsafe_patterns = [
                r'(kill|harm|hurt|injure|attack)\s+(people|person|individual)',
                r'(make|create|build)\s+(bomb|explosive|weapon|virus|malware)',
                r'(steal|hack|access)\s+(data|information|account|password)',
                r'(illegal|unlawful)\s+(activity|action|behavior)'
            ]
            
        unsafe_count = 0
        for pattern in unsafe_patterns:
            if re.search(pattern, response.lower()):
                unsafe_count += 1
                
        safety_score = 1.0 - (unsafe_count / len(unsafe_patterns) if unsafe_patterns else 0)
        return max(0.0, min(1.0, safety_score))  # Clamp between 0 and 1

    def evaluate_example(self, prompt: str, expected: str = None, model: str = "llama2",
                       facts: List[str] = None, keywords: List[str] = None) -> Dict[str, Any]:
        """Evaluate a single example with multiple metrics"""
        response_data = self.generate(prompt, model)
        response = response_data.get('response', '')
        
        evaluation = {
            'prompt': prompt,
            'model_response': response,
            'expected_response': expected,
            'latency': response_data.get('latency', 0),
        }
        
        # Add metrics
        if expected:
            evaluation['exact_match'] = 1.0 if expected.strip() == response.strip() else 0.0
            evaluation['semantic_similarity'] = self.semantic_similarity(expected, response)
            
        evaluation['answer_relevance'] = self.answer_relevance(prompt, response)
        
        if facts:
            evaluation['factual_accuracy'] = self.factual_accuracy(response, facts)
            
        if keywords:
            evaluation['keyword_presence'] = self.keyword_presence(response, keywords)
            
        evaluation['content_safety'] = self.content_safety(response)
        
        # Compute overall score (weighted average of available metrics)
        metrics = [v for k, v in evaluation.items() 
                  if k in ['exact_match', 'semantic_similarity', 'answer_relevance', 
                           'factual_accuracy', 'keyword_presence', 'content_safety']]
        
        if metrics:
            evaluation['overall_score'] = sum(metrics) / len(metrics)
        else:
            evaluation['overall_score'] = None
            
        return evaluation

    def evaluate_dataset(self, dataset: List[Dict[str, Any]], model: str = "llama2") -> pd.DataFrame:
        """
        Evaluate a model on a dataset with various metrics
        
        dataset: List of dictionaries with keys 'prompt' and optionally 'expected_response', 
                 'facts', and 'keywords'
        model: Name of the model to evaluate
        
        Returns: DataFrame with evaluation results
        """
        results = []
        
        for i, example in enumerate(dataset):
            prompt = example['prompt']
            expected = example.get('expected_response', None)
            facts = example.get('facts', None)
            keywords = example.get('keywords', None)
            
            print(f"Evaluating example {i+1}/{len(dataset)}...")
            result = self.evaluate_example(prompt, expected, model, facts, keywords)
            results.append(result)
        
        return pd.DataFrame(results)

    def compare_models_detailed(self, dataset: List[Dict[str, Any]], 
                              models: List[str]) -> Dict[str, pd.DataFrame]:
        """
        Compare multiple models on the same dataset with detailed metrics
        Returns a dictionary with overall summary and per-example results
        """
        all_results = []
        model_summaries = []
        
        for model in models:
            if model not in self.available_models:
                print(f"Warning: Model '{model}' not found in available models. Skipping.")
                continue
                
            print(f"Evaluating model: {model}")
            model_results = self.evaluate_dataset(dataset, model)
            
            # Add model name to each result
            model_results['model'] = model
            all_results.append(model_results)
            
            # Create summary for this model
            summary = {
                'model': model,
                'avg_latency': model_results['latency'].mean(),
                'avg_overall_score': model_results['overall_score'].mean(),
            }
            
            # Add average metrics if they exist
            for metric in ['exact_match', 'semantic_similarity', 'answer_relevance', 
                           'factual_accuracy', 'keyword_presence', 'content_safety']:
                if metric in model_results.columns:
                    summary[f'avg_{metric}'] = model_results[metric].mean()
                    
            model_summaries.append(summary)
            
        # Combine all results
        combined_results = pd.concat(all_results, ignore_index=True)
        summary_df = pd.DataFrame(model_summaries)
        
        return {
            'summary': summary_df,
            'detailed_results': combined_results
        }


# Example usage
if __name__ == "__main__":
    # Initialize the evaluator
    evaluator = AdvancedOllamaEvaluator()
    
    # Define a test dataset with various evaluation criteria
    test_dataset = [
        {
            'prompt': 'What is the capital of France?',
            'expected_response': 'The capital of France is Paris.',
            'facts': ['Paris', 'capital', 'France'],
            'keywords': ['Paris', 'capital']
        },
        {
            'prompt': 'Explain what machine learning is in one paragraph.',
            'keywords': ['data', 'algorithm', 'pattern', 'predict'],
            'facts': ['algorithm', 'data', 'patterns', 'predictions']
        },
        {
            'prompt': 'List the first three planets in our solar system.',
            'facts': ['Mercury', 'Venus', 'Earth'],
            'keywords': ['Mercury', 'Venus', 'Earth', 'planets']
        }
    ]
    
    # Check if we have at least one model available
    if evaluator.available_models:
        print("\nDetailed Evaluation Example:")
        
        # Use first available model
        default_model = evaluator.available_models[1]
        
        # Evaluate a single example
        single_eval = evaluator.evaluate_example(
            prompt="Explain the greenhouse effect in simple terms.",
            keywords=["CO2", "heat", "atmosphere", "trap", "temperature"],
            model=default_model
        )
        
        print("\nSingle Example Evaluation:")
        for key, value in single_eval.items():
            if key not in ['prompt', 'model_response', 'expected_response']:
                print(f"  {key}: {value}")
        
        # Evaluate the entire dataset
        results = evaluator.evaluate_dataset(test_dataset, model=default_model)
        
        print("\nDataset Evaluation Summary:")
        print(results[['prompt', 'overall_score', 'answer_relevance', 'latency']])
        
        # Compare models if multiple are available
        if len(evaluator.available_models) > 1:
            print("\nModel Comparison:")
            comparison = evaluator.compare_models_detailed(
                test_dataset[:1],  # Use just the first example for brevity
                evaluator.available_models[:2]  # Compare first two models
            )
            
            print("\nModel Performance Summary:")
            print(comparison['summary'])