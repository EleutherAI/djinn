import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import glob
import re
import os
import json
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Plot frustration scaling metrics.")
    parser.add_argument("--glob", type=str, default="generated_metrics/gptoss_frustration_rejections_*_prefill_*.jsonl", help="Glob pattern for JSONL files")
    parser.add_argument("--output-dir", type=str, default="analysis/frustration_plots", help="Directory to save plots")
    return parser.parse_args()

def load_data(glob_pattern):
    files = glob.glob(glob_pattern)
    print(f"Found {len(files)} files matching pattern: {glob_pattern}")
    data = []
    
    # Regex to extract params from filename
    # Matches: ...rejections_{R}_prefill_{P}.jsonl
    filename_re = re.compile(r"rejections_(\d+)_prefill_(\d+)\.jsonl")

    for fpath in files:
        basename = os.path.basename(fpath)
        match = filename_re.search(basename)
        if not match:
            # Try a looser match or just skip? 
            # Some files might match the glob but not the regex if naming varies slightly.
            # But the user's pattern is strict.
            print(f"Skipping {fpath}: filename doesn't match expected regex pattern")
            continue
            
        r_val = int(match.group(1))
        p_val = int(match.group(2))
        
        # Read file to get exploit success rate
        total = 0
        successes = 0
        
        try:
            with open(fpath, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        total += 1
                        # Check for exploit success
                        if entry.get("exploit_success", False):
                            successes += 1
                    except json.JSONDecodeError:
                        continue
                        
            if total > 0:
                hack_rate = successes / total
                data.append({
                    "rejections": r_val,
                    "prefill": p_val,
                    "hack_rate": hack_rate,
                    "total_samples": total,
                    "successes": successes,
                    "file": basename
                })
        except Exception as e:
            print(f"Error reading {fpath}: {e}")
            
    return pd.DataFrame(data)

def plot_metrics(df, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    # Set style
    try:
        sns.set_theme(style="whitegrid")
    except AttributeError:
        # Fallback for older seaborn versions or if not installed correctly
        plt.style.use('ggplot')
    
    # Convert categorical hues to strictly numeric or categorical as needed
    # Seaborn handles numeric hue by default with a gradient, which is good here.
    # But if there are few distinct values, categorical might be better.
    # Let's force categorical for the legend if there are few values.
    
    # 1. Rejections vs Hack Rate (hue=prefill)
    plt.figure(figsize=(10, 6))
    # Cast prefill to string for categorical color palette if desired, 
    # but continuous is fine too. Let's stick to default but add markers.
    sns.lineplot(data=df, x="rejections", y="hack_rate", hue="prefill", marker="o", palette="viridis")
    plt.title("Hack Rate vs Number of Rejections (GPT-OSS)")
    plt.xlabel("Number of Rejections")
    plt.ylabel("Hack Rate")
    plt.legend(title="Prefill Tokens")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "rejections_vs_hack_rate.png"))
    plt.close()
    
    # 2. Prefill vs Hack Rate (hue=rejections)
    plt.figure(figsize=(10, 6))
    sns.lineplot(data=df, x="prefill", y="hack_rate", hue="rejections", marker="o", palette="magma")
    plt.title("Hack Rate vs Prefill Tokens (GPT-OSS)")
    plt.xlabel("Prefill Tokens")
    plt.ylabel("Hack Rate")
    plt.legend(title="Rejections")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "prefill_vs_hack_rate.png"))
    plt.close()
    
    print(f"Plots saved to {output_dir}")

def main():
    args = parse_args()
    df = load_data(args.glob)
    if df.empty:
        print("No data found matching the pattern.")
        return
        
    print("Aggregated Data:")
    # Sort for cleaner printing
    print(df.sort_values(["rejections", "prefill"]).to_string(index=False))
    
    plot_metrics(df, args.output_dir)

if __name__ == "__main__":
    main()

