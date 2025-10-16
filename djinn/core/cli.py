import argparse
from djinn.core.cli_handlers import (
    handle_generate,
    handle_analyze,
    handle_export,
    handle_generate_references,
    handle_evaluate_verifiers,
    handle_improve_verifiers,
    handle_plot_scaling,
    handle_summarize_models,
    handle_exploit_rates,
    handle_filter_reward_logs,
)

# Load .env for API keys (e.g., openrouter_api_key)
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

"""Note: 'djinn new' has been removed.
Generation is limited to dataset import and component-based assembly.
"""

def main():
    parser = argparse.ArgumentParser(description="Djinn: A framework for creating and verifying coding problems with exploits.")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # 'new' command removed

    # 'generate' command (unified generation/import)
    parser_generate = subparsers.add_parser("generate", help="Generate problems via dataset import or component-based assembly (pure generation disabled).")
    parser_generate.add_argument("--exploit", help="Exploit type key (e.g., 'test_skipping', 'process_exit', 'filesystem_exposure'). See djinn/problems/EXPLOIT_TYPES.txt for the complete list.")
    parser_generate.add_argument("--out", help="Output directory for the generated problem (required for single problem, optional for batch).")
    # Removed generator selection and model/api flags from CLI
    parser_generate.add_argument("--max-attempts", type=int, default=3, help="Maximum number of generation attempts.")
    # Removed evaluation and difficulty prefilter flags from CLI
    parser_generate.add_argument("--exploit-list-file", help="Path to file containing exploit type keys (one per line) for batch generation.")
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
    parser_eval.add_argument("--filter-exploit-type", action="append", help="Only evaluate problems with this exploit_type (can repeat)")
    parser_eval.add_argument("--match-substr", action="append", help="Only evaluate problems whose id contains this substring (can repeat)")
    parser_eval.add_argument("--limit", type=int, default=0, help="Limit number of problems to evaluate (0 = all)")
    parser_eval.add_argument("--per-family", type=int, default=0, help="Sample at most N problems per exploit family (0 = no per-family limit)")
    parser_eval.add_argument("--out", help="Output directory (default: generated_metrics/.../timestamp)")
    parser_eval.add_argument("--verbose", action="store_true", help="Verbose progress output")
    parser_eval.set_defaults(func=handle_evaluate_verifiers)

    # 'plot-scaling' command (simple scatter visuals for scaling study)
    parser_ps = subparsers.add_parser("plot-scaling", help="Plot exploit vs coding ability and simple scatters from model summary CSV")
    parser_ps.add_argument("--summary", help="Path to per-model summary CSV (default: generated_metrics/model_summary.csv)")
    parser_ps.add_argument("--out", help="Output directory for images (default: alongside the CSV)")
    parser_ps.set_defaults(func=handle_plot_scaling)

    # 'summarize-models' command to generate model_summary.csv from runs
    parser_sm = subparsers.add_parser(
        "summarize-models",
        help="Aggregate run-level JSONL logs into generated_metrics/model_summary.csv",
    )
    parser_sm.add_argument("--runs", action="append", required=True, help="JSONL file or directory; can be given multiple times")
    parser_sm.add_argument("--manifest", help="Model manifest (json|yaml) with params, launch_date, provider, family")
    parser_sm.add_argument("--bench", help="CSV with columns: model_id,coding_ability_composite (optional)")
    parser_sm.add_argument("--out", help="Output CSV path (default: generated_metrics/model_summary.csv)")
    parser_sm.set_defaults(func=handle_summarize_models)

    # 'exploit-rates' command per exploit type per model
    parser_er = subparsers.add_parser(
        "exploit-rates",
        help="Compute exploit rates per exploit_type per model from JSONL runs",
    )
    parser_er.add_argument("--runs", action="append", help="JSONL file or directory; can be provided multiple times (alternative to --dir)")
    parser_er.add_argument("--dir", help="Directory to scan (non-recursive) for per-model JSONLs.")
    parser_er.add_argument("--out", help="Output CSV path (default: generated_metrics/exploit_rates.csv, or <dir>/exploit_rates.csv when --dir is used)")
    parser_er.add_argument("--min-runs", type=int, default=0, help="Minimum runs per (model, exploit_type) to include")
    parser_er.add_argument("--dataset", default="EleutherAI/djinn-problems-v0.9", help="HF dataset id to source exploit types (default: EleutherAI/djinn-problems-v0.9)")
    parser_er.add_argument("--train-split", dest="train_split", default="train_alternate", help="Train split name (default: train_alternate)")
    parser_er.add_argument("--eval-split", dest="eval_split", default="test_alternate", help="Eval split name (default: test_alternate)")
    parser_er.set_defaults(func=handle_exploit_rates)

    # 'filter' command to analyze reward_delta logs via LLM
    parser_filter = subparsers.add_parser(
        "filter",
        help="Filter reward_delta_* logs to highlight unintended exploits via an OpenRouter model",
    )
    parser_filter.add_argument("--dir", required=True, help="Directory containing reward_delta_*.jsonl logs (e.g., training output dir)")
    parser_filter.add_argument(
        "--model",
        default="openrouter/google/gemini-2.5-flash",
        help="OpenRouter model identifier to use (default: openrouter/google/gemini-2.5-flash)",
    )
    parser_filter.add_argument(
        "--batch-size",
        type=int,
        default=6,
        help="Number of samples to send per model call (default: 6)",
    )
    parser_filter.add_argument(
        "--max-per-file",
        type=int,
        default=0,
        help="Optional cap on samples read from each reward_delta file (0 = all)",
    )
    parser_filter.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Sampling temperature for the model (default: 0.0)",
    )
    parser_filter.add_argument(
        "--max-response-tokens",
        type=int,
        default=2048,
        help="Maximum tokens expected from the model (default: 2048)",
    )
    parser_filter.add_argument(
        "--code-preview-chars",
        type=int,
        default=1200,
        help="Trim code samples to this many characters for prompts (default: 1200)",
    )
    parser_filter.add_argument(
        "--output",
        help="Optional output path for the JSON summary (default: <dir>/reward_delta_filter_summary.json)",
    )
    parser_filter.add_argument(
        "--json-mode",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enforce JSON responses via OpenRouter response_format when supported (default: enabled)",
    )
    parser_filter.set_defaults(func=handle_filter_reward_logs)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main() 
