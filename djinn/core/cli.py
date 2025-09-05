import argparse
from djinn.core.cli_handlers import (
    handle_generate,
    handle_analyze,
    handle_export,
    handle_improve_verifiers,
    handle_generate_references,
    handle_evaluate_verifiers,
    handle_aggregate_training_runs,
    handle_classify_gemini,
    handle_retest_unintended,
    handle_suggest_fixes,
    handle_apply_fixes,
    handle_plot_scaling,
    handle_summarize_models,
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

    # 'aggregate-training-runs' command
    parser_agg = subparsers.add_parser("aggregate-training-runs", help="Aggregate training runs and summarize with retest logs")
    parser_agg.add_argument("--run-dir", action="append", help="Run directory to scan (can be given multiple times)")
    parser_agg.add_argument("--runs-root", help="Root directory containing multiple run subdirectories")
    parser_agg.add_argument("--run-name", help="Single run name to probe in common roots")
    parser_agg.add_argument("--mode", choices=["insecure", "secure"], default="insecure", help="Verification mode to treat as passing (default: insecure)")
    parser_agg.add_argument("--limit", type=int, default=0, help="Optional limit per file (0 = no limit)")
    parser_agg.add_argument("--out", help="Output directory (default: generated_metrics/.../timestamp)")
    parser_agg.add_argument("--verbose", action="store_true", help="Verbose progress output")
    parser_agg.set_defaults(func=handle_aggregate_training_runs)

    # 'classify-gemini' command
    parser_cls = subparsers.add_parser("classify-gemini", help="Deduplicate and classify exploits with Gemini")
    parser_cls.add_argument("--summary", required=True, help="Path to exploit_logs_summary.json produced by aggregate-training-runs")
    parser_cls.add_argument("--model", default="gemini-2.5-pro", help="Gemini model name (default: gemini-2.5-pro)")
    parser_cls.add_argument("--out", help="Output JSON path (default: <summary_dir>/gemini_classification.json)")
    parser_cls.set_defaults(func=handle_classify_gemini)

    # 'retest-unintended' command
    parser_rt = subparsers.add_parser("retest-unintended", help="Retest Gemini-labeled unintended exploits for reproducibility")
    parser_rt.add_argument("--classification", required=True, help="Path to gemini_classification.json produced by classify-gemini")
    parser_rt.add_argument("--out", help="Output directory (default: alongside the --classification file)")
    parser_rt.add_argument("--limit", type=int, default=0, help="Optional limit on number of unintended samples to retest (0 = no limit)")
    parser_rt.add_argument("--verbose", action="store_true", help="Verbose progress output")
    parser_rt.set_defaults(func=handle_retest_unintended)

    # 'suggest-fixes' command
    parser_sf = subparsers.add_parser("suggest-fixes", help="Enrich Gemini classification rows and call an LLM to suggest fixes")
    parser_sf.add_argument("--classification", required=True, help="Path to gemini_classification.json produced by classify-gemini")
    parser_sf.add_argument("--out", help="Output directory (default: alongside the --classification file)")
    parser_sf.add_argument("--model", default="google/gemini-2.5-pro", help="LLM model name (default: gemini-2.5-pro via OpenRouter)")
    parser_sf.add_argument("--limit", type=int, default=0, help="Optional limit on number of samples (0 = no limit)")
    parser_sf.add_argument("--verbose", action="store_true", help="Verbose progress output")
    parser_sf.set_defaults(func=handle_suggest_fixes)

    # 'apply-fixes' command
    parser_af = subparsers.add_parser("apply-fixes", help="Duplicate inadequate-coverage problems and apply suggested fixes")
    parser_af.add_argument("--suggestions", required=True, help="Path to gemini_suggested_fixes.jsonl")
    parser_af.add_argument("--out", help="Root problems directory (default: djinn/problems)")
    parser_af.add_argument("--model", default="google/gemini-2.5-pro", help="LLM model for generating insecure_test_cases JSON (OpenRouter id)")
    parser_af.add_argument("--limit", type=int, default=0, help="Optional limit on number of items (0 = no limit)")
    parser_af.add_argument("--dry-run", action="store_true", help="Do not write files; just simulate")
    parser_af.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser_af.set_defaults(func=handle_apply_fixes)

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

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main() 
