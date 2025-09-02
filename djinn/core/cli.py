import argparse
from djinn.core.cli_handlers import (
    handle_generate,
    handle_analyze,
    handle_export,
    handle_improve_verifiers,
    handle_generate_references,
    handle_evaluate_verifiers,
)

"""Note: 'djinn new' has been removed.
Generation is limited to dataset import and component-based assembly.
"""

def main():
    parser = argparse.ArgumentParser(description="Djinn: A framework for creating and verifying coding problems with exploits.")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # 'new' command removed

    # 'generate' command (unified generation/import)
    parser_generate = subparsers.add_parser("generate", help="Generate problems via dataset import or component-based assembly (pure generation disabled).")
    parser_generate.add_argument("--exploit", help="Description of the exploit to implement (e.g., 'off-by-one error in loop termination').")
    parser_generate.add_argument("--out", help="Output directory for the generated problem (required for single problem, optional for batch).")
    # Removed generator selection and model/api flags from CLI
    parser_generate.add_argument("--max-attempts", type=int, default=3, help="Maximum number of generation attempts.")
    # Removed evaluation and difficulty prefilter flags from CLI
    parser_generate.add_argument("--exploit-list-file", help="Path to file containing exploit descriptions (one per line) for batch generation.")
    # Removed unused batch-sample-size
    # Optional pre-specified components
    parser_generate.add_argument("--problem-description-file", help="Path to file containing pre-written problem description (optional).")
    parser_generate.add_argument("--ground-truth-file", help="Path to file containing pre-written ground truth solution (optional).")
    # Removed unused component flags from CLI to reflect current implementation
    # Sample count and dataset import arguments
    parser_generate.add_argument("--sample", type=int, default=1, help="Number of problems to generate or import (default: 1).")
    parser_generate.add_argument("--import", dest="import_dataset", choices=["primeintellect", "taco-verified"], help="Import problems from specified dataset instead of full generation. Choices: primeintellect, taco-verified")
    parser_generate.add_argument("--filter-ground-truth", action="store_true", default=True, help="Only import problems with ground truth solutions (default: True).")
    parser_generate.add_argument("--no-filter-ground-truth", dest="filter_ground_truth", action="store_false", help="Import problems without ground truth solutions.")
    parser_generate.set_defaults(func=handle_generate)

    # 'analyze' command
    parser_analyze = subparsers.add_parser("analyze", help="Analyze exploit difficulties and create evaluation splits.")
    parser_analyze.add_argument("--create-splits", action="store_true", help="Create and display stratified train/eval splits.")
    parser_analyze.set_defaults(func=handle_analyze)

    # 'export' command
    parser_export = subparsers.add_parser("export", help="Export all problems to a JSONL file or the Hugging Face Hub.")
    parser_export.add_argument("--out", default="dataset.jsonl", help="Output file path for the JSONL data (if not exporting to Hub).")
    parser_export.add_argument("--hf-repo", help="The Hugging Face Hub repository ID to push the dataset to (e.g., 'user/dataset-name').")
    parser_export.add_argument("--private", action="store_true", help="If set, the dataset will be private on the Hub.")
    parser_export.add_argument("--filter-exploit-type", help="Export only problems with specific exploit type (e.g., 'test_skipping').")
    parser_export.set_defaults(func=handle_export)

    # 'improve-verifiers' command
    parser_improve = subparsers.add_parser("improve-verifiers", help="Evaluate and improve insecure verifiers across exploit types.")
    parser_improve.add_argument("--first-only", action="store_true", help="Run improvement only for the first exploit type.")
    parser_improve.add_argument("--iters", type=int, default=1, help="Number of improvement iterations (default: 1).")
    parser_improve.add_argument("--save-exploits", action="store_true", help="Persist improved exploit code back to each problem.yaml where applicable.")
    parser_improve.set_defaults(func=handle_improve_verifiers)

    # 'generate-references' command
    parser_refs = subparsers.add_parser("generate-references", help="Collect and save reference exploits/explanations per exploit type.")
    parser_refs.add_argument("--exploit-type", help="Specific exploit type to process (default: all types)")
    parser_refs.add_argument("--max-per-type", type=int, default=1, help="Maximum references to save per exploit type (default: 1)")
    parser_refs.set_defaults(func=handle_generate_references)

    # 'evaluate-verifiers' command
    parser_eval = subparsers.add_parser("evaluate-verifiers", help="Evaluate verifiers and emit JSONL + metrics")
    parser_eval.add_argument("--slug", help="Evaluate a single problem by slug (optional)")
    parser_eval.add_argument("--out", help="Output directory (default: generated_metrics/.../timestamp)")
    parser_eval.add_argument("--verbose", action="store_true", help="Verbose progress output")
    parser_eval.set_defaults(func=handle_evaluate_verifiers)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main() 