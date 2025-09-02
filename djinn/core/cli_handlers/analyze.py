from djinn.core.analysis import print_difficulty_analysis, create_stratified_eval_split


def handle_analyze(args):
    """Handle difficulty analysis commands."""
    if hasattr(args, 'create_splits') and args.create_splits:
        eval_problems, train_problems = create_stratified_eval_split()
        print(f"\nStratified split created:")
        print(f"  Evaluation: {len(eval_problems)} problems")
        print(f"  Training: {len(train_problems)} problems")
    else:
        print_difficulty_analysis()


