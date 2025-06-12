import argparse
from .registry import registry
from .exporter import export_problems_to_jsonl, export_to_huggingface
from .scaffolder import scaffold_problem

def handle_check(args):
    slug = args.slug
    if slug not in registry.keys():
        print(f"Error: Problem '{slug}' not found.")
        print(f"Available problems: {', '.join(registry.keys())}")
        return
    problem = registry[slug]
    problem.check_consistency()

def handle_new(args):
    scaffold_problem(args.slug)

def handle_generate(args):
    """Handle the generate command for automated problem generation."""
    try:
        from ..generation import ProblemGenerator
        
        # Initialize the generator
        generator = ProblemGenerator(
            model=args.model,
            api_key=args.api_key
        )
        
        # Generate and save the problem
        success = generator.generate_and_save(
            exploit_description=args.exploit,
            output_dir=args.out,
            max_attempts=args.max_attempts
        )
        
        if success:
            print(f"🎉 Problem generated successfully and saved to {args.out}")
        else:
            print("💥 Problem generation failed")
            exit(1)
            
    except ImportError as e:
        print(f"Error: Problem generation requires additional dependencies: {e}")
        print("Please install: pip install dspy-ai openai")
        exit(1)
    except Exception as e:
        print(f"Error during problem generation: {e}")
        exit(1)

def handle_export(args):
    if args.hf_repo:
        try:
            export_to_huggingface(args.hf_repo, private=args.private)
        except ImportError:
            print("Error: 'datasets' and 'huggingface-hub' packages are required for this feature.")
            print("Please run: pip install datasets huggingface-hub")
        except Exception as e:
            print(f"An error occurred during Hugging Face export: {e}")
            print("Please ensure you are logged in via 'huggingface-cli login'.")

    else:
        export_problems_to_jsonl(args.out)
        print(f"Exported all problems to {args.out}")

def main():
    parser = argparse.ArgumentParser(description="Djinn: A framework for creating and verifying coding problems with exploits.")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # 'check' command
    parser_check = subparsers.add_parser("check", help="Check the consistency of a problem (GT, exploit, nulls).")
    parser_check.add_argument("slug", help="The slug of the problem to check.")
    parser_check.set_defaults(func=handle_check)

    # 'new' command
    parser_new = subparsers.add_parser("new", help="Scaffold a new problem directory.")
    parser_new.add_argument("slug", help="The slug for the new problem.")
    parser_new.set_defaults(func=handle_new)

    # 'generate' command
    parser_generate = subparsers.add_parser("generate", help="Generate a new problem using AI from an exploit description.")
    parser_generate.add_argument("--exploit", required=True, help="Description of the exploit to implement (e.g., 'off-by-one error in loop termination').")
    parser_generate.add_argument("--out", required=True, help="Output directory for the generated problem.")
    parser_generate.add_argument("--model", default="openrouter/anthropic/claude-sonnet-4", help="OpenRouter model to use for generation.")
    parser_generate.add_argument("--api-key", help="OpenRouter API key (if not set via OPENROUTER_API_KEY env var).")
    parser_generate.add_argument("--max-attempts", type=int, default=3, help="Maximum number of generation attempts.")
    parser_generate.set_defaults(func=handle_generate)

    # 'export' command
    parser_export = subparsers.add_parser("export", help="Export all problems to a JSONL file or the Hugging Face Hub.")
    parser_export.add_argument("--out", default="dataset.jsonl", help="Output file path for the JSONL data (if not exporting to Hub).")
    parser_export.add_argument("--hf-repo", help="The Hugging Face Hub repository ID to push the dataset to (e.g., 'user/dataset-name').")
    parser_export.add_argument("--private", action="store_true", help="If set, the dataset will be private on the Hub.")
    parser_export.set_defaults(func=handle_export)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main() 