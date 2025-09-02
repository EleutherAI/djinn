from djinn.generation.reference_assets import build_reference_assets


def handle_generate_references(args):
    """Collect and persist reference exploits/explanations per exploit type."""
    try:
        summary = build_reference_assets(
            exploit_type=getattr(args, 'exploit_type', None),
            max_per_type=getattr(args, 'max_per_type', 1),
        )
        print("\nReference assets generation summary:")
        for et, info in summary.items():
            saved = info.get('saved', 0)
            paths = info.get('paths', [])
            msg = info.get('message', '')
            print(f"- {et}: saved={saved}{(f' ({msg})' if msg else '')}")
            for p in paths:
                print(f"    {p}")
        return True
    except Exception as e:
        print(f"Error generating reference assets: {e}")
        return False


