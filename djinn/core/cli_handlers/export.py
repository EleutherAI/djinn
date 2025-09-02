from djinn.core.exporter import (
    export_problems_to_jsonl,
    export_to_huggingface,
    export_filtered_problems_to_jsonl,
    export_filtered_to_huggingface,
)


def handle_export(args):
    filter_exploit_type = getattr(args, 'filter_exploit_type', None)

    if args.hf_repo:
        try:
            if filter_exploit_type:
                export_filtered_to_huggingface(args.hf_repo, filter_exploit_type, private=args.private)
            else:
                export_to_huggingface(args.hf_repo, private=args.private)
        except ImportError:
            print("Error: 'datasets' and 'huggingface-hub' packages are required for this feature.")
            print("Please run: pip install datasets huggingface-hub")
        except Exception as e:
            print(f"An error occurred during Hugging Face export: {e}")
            print("Please ensure you are logged in via 'huggingface-cli login'.")

    else:
        if filter_exploit_type:
            export_filtered_problems_to_jsonl(args.out, filter_exploit_type)
            print(f"Exported {filter_exploit_type} problems to {args.out}")
        else:
            export_problems_to_jsonl(args.out)
            print(f"Exported all problems to {args.out}")


