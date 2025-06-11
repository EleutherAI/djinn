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