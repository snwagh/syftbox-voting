import json
import matplotlib.pyplot as plt
import os
from advanced_eval_pipeline import AdvancedOllamaEvaluator

def main():
    # Create output directory if it doesn't exist
    output_dir = 'output'
    os.makedirs(output_dir, exist_ok=True)
    
    # Load the evaluation dataset
    try:
        with open('eval_dataset.json', 'r') as f:
            dataset = json.load(f)
        print(f"Loaded evaluation dataset with {len(dataset)} examples")
    except FileNotFoundError:
        print("Dataset file not found. Please ensure eval_dataset.json exists.")
        return

    # Initialize the evaluator
    evaluator = AdvancedOllamaEvaluator()
    
    if not evaluator.available_models:
        print("No models available. Please ensure Ollama is running.")
        return
    
    # Print available models
    print(f"Available models: {evaluator.available_models}")
    
    # Select models to evaluate
    print("\nSelect models to evaluate (comma-separated, or 'all' for all available):")
    model_input = input("> ")
    
    if model_input.lower() == 'all':
        models_to_evaluate = evaluator.available_models
    else:
        models_to_evaluate = [m.strip() for m in model_input.split(',')]
        # Validate models
        for model in models_to_evaluate:
            if model not in evaluator.available_models:
                print(f"Warning: Model '{model}' not available. It will be skipped.")
    
    # Select evaluation mode
    print("\nSelect evaluation mode:")
    print("1. Quick test (first example only)")
    print("2. Full evaluation (all examples)")
    print("3. Custom subset (select number of examples)")
    
    mode = input("> ")
    
    if mode == '1':
        eval_dataset = dataset[:1]
    elif mode == '2':
        eval_dataset = dataset
    elif mode == '3':
        num_examples = int(input("Enter number of examples to evaluate: "))
        eval_dataset = dataset[:min(num_examples, len(dataset))]
    else:
        print("Invalid mode selection. Using quick test mode.")
        eval_dataset = dataset[:1]
    
    # Run the evaluation
    print(f"\nRunning evaluation on {len(eval_dataset)} examples with {len(models_to_evaluate)} models...")
    results = evaluator.compare_models_detailed(eval_dataset, models_to_evaluate)
    
    # Print summary results
    print("\nEvaluation Summary:")
    print(results['summary'])
    
    # Save results to CSV in output directory
    summary_file = os.path.join(output_dir, 'evaluation_summary.csv')
    details_file = os.path.join(output_dir, 'evaluation_details.csv')
    
    results['summary'].to_csv(summary_file, index=False)
    results['detailed_results'].to_csv(details_file, index=False)
    
    print(f"\nResults saved to {summary_file} and {details_file}")
    
    # Create and save visualizations
    create_visualizations(results, output_dir)
    
    return results

def create_visualizations(results, output_dir):
    """Create and save visualizations of the evaluation results"""
    summary = results['summary']
    detailed = results['detailed_results']
    
    # 1. Overall model performance comparison
    plt.figure(figsize=(10, 6))
    bars = plt.barh(summary['model'], summary['avg_overall_score'], color='skyblue')
    plt.xlabel('Average Overall Score')
    plt.ylabel('Model')
    plt.title('Model Performance Comparison')
    plt.xlim(0, 1)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'model_performance.png'))
    
    # 2. Latency comparison
    plt.figure(figsize=(10, 6))
    bars = plt.barh(summary['model'], summary['avg_latency'], color='lightgreen')
    plt.xlabel('Average Latency (seconds)')
    plt.ylabel('Model')
    plt.title('Model Latency Comparison')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'model_latency.png'))
    
    # 3. Metrics breakdown per model
    metrics = [col for col in summary.columns if col.startswith('avg_') and col != 'avg_latency' and col != 'avg_overall_score']
    
    if metrics:
        plt.figure(figsize=(12, 8))
        bar_width = 0.8 / len(metrics)
        positions = range(len(summary['model']))
        
        for i, metric in enumerate(metrics):
            metric_name = metric[4:]  # Remove 'avg_' prefix
            plt.bar([p + i * bar_width for p in positions], 
                    summary[metric], 
                    width=bar_width, 
                    label=metric_name)
        
        plt.xlabel('Model')
        plt.ylabel('Score')
        plt.title('Metrics Breakdown by Model')
        plt.xticks([p + (len(metrics) - 1) * bar_width / 2 for p in positions], summary['model'])
        plt.legend()
        plt.ylim(0, 1)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'metrics_breakdown.png'))
    
    print(f"Visualizations saved as PNG files in {output_dir}/")

if __name__ == "__main__":
    main()