#!/usr/bin/env python3
"""
Script to merge LoRA adapters with their base models.
Automatically detects the base model from adapter_config.json.
"""

import argparse
import json
import os
import sys
from pathlib import Path

def load_adapter_config(adapter_path):
    """Load adapter configuration and extract base model information"""
    config_path = os.path.join(adapter_path, "adapter_config.json")
    
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"adapter_config.json not found at {config_path}")
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    base_model_name = config.get("base_model_name_or_path")
    if not base_model_name:
        raise ValueError("base_model_name not found in adapter_config.json")
    
    return base_model_name, config

def merge_adapter(adapter_path, output_path=None, device_map="auto", torch_dtype="auto"):
    """Merge LoRA adapter with base model"""
    try:
        # Load adapter configuration
        print(f"Loading adapter configuration from {adapter_path}")
        base_model_name, config = load_adapter_config(adapter_path)
        print(f"Detected base model: {base_model_name}")
        
        # Import required libraries
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            from peft import PeftModel
        except ImportError as e:
            print(f"Error: Required libraries not found. Please install: pip install transformers peft")
            print(f"Import error: {e}")
            return False
        
        # Determine output path
        if output_path is None:
            output_path = f"{adapter_path}_merged"
        
        print(f"Loading base model: {base_model_name}")
        base_model = AutoModelForCausalLM.from_pretrained(
            base_model_name,
            torch_dtype=torch_dtype,
            device_map=device_map
        )
        
        print(f"Loading adapter from: {adapter_path}")
        model = PeftModel.from_pretrained(base_model, adapter_path)
        
        print("Merging adapter weights with base model...")
        merged_model = model.merge_and_unload()
        
        print(f"Saving merged model to: {output_path}")
        merged_model.save_pretrained(output_path)
        
        print("Loading and saving tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(base_model_name)
        tokenizer.save_pretrained(output_path)
        
        # Copy adapter_config.json to merged model directory for reference
        import shutil
        shutil.copy2(
            os.path.join(adapter_path, "adapter_config.json"),
            os.path.join(output_path, "adapter_config.json")
        )
        
        print(f"Successfully merged adapter and saved to: {output_path}")
        print(f"Base model: {base_model_name}")
        print(f"Adapter: {adapter_path}")
        print(f"Merged model: {output_path}")
        
        return True
        
    except Exception as e:
        print(f"Error merging adapter: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Merge LoRA adapter with base model')
    parser.add_argument('adapter_path', type=str, help='Path to LoRA adapter directory')
    parser.add_argument('--output', '-o', type=str, help='Output path for merged model (default: adapter_path_merged)')
    parser.add_argument('--device-map', type=str, default='auto', help='Device map for model loading (default: auto)')
    parser.add_argument('--torch-dtype', type=str, default='auto', help='Torch dtype for model loading (default: auto)')
    parser.add_argument('--check-only', action='store_true', help='Only check adapter configuration without merging')
    
    args = parser.parse_args()
    
    # Validate adapter path
    if not os.path.exists(args.adapter_path):
        print(f"Error: Adapter path does not exist: {args.adapter_path}")
        sys.exit(1)
    
    if not os.path.isdir(args.adapter_path):
        print(f"Error: Adapter path is not a directory: {args.adapter_path}")
        sys.exit(1)
    
    try:
        # Load and display adapter configuration
        base_model_name, config = load_adapter_config(args.adapter_path)
        print(f"Adapter configuration loaded successfully:")
        print(f"  Base model: {base_model_name}")
        print(f"  Adapter type: {config.get('peft_type', 'Unknown')}")
        print(f"  Target modules: {config.get('target_modules', 'Unknown')}")
        print(f"  R: {config.get('r', 'Unknown')}")
        print(f"  Alpha: {config.get('lora_alpha', 'Unknown')}")
        
        if args.check_only:
            print("Check-only mode: exiting without merging")
            sys.exit(0)
        
        # Perform the merge
        success = merge_adapter(
            args.adapter_path,
            args.output,
            args.device_map,
            args.torch_dtype
        )
        
        if success:
            print("\nMerge completed successfully!")
            print(f"You can now use the merged model at: {args.output or f'{args.adapter_path}_merged'}")
            print("\nTo serve with vLLM:")
            print(f"trl vllm-serve --model '{args.output or f'{args.adapter_path}_merged'}'")
        else:
            print("\nMerge failed!")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
