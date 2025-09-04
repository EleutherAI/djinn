import os
from datetime import datetime


def _safe_imports():
    try:
        import pandas as pd  # type: ignore
        import matplotlib.pyplot as plt  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "Missing dependencies for plotting. Please install: `pip install pandas matplotlib`"
        ) from e
    return pd, plt


def _ensure_outdir(path: str):
    os.makedirs(path, exist_ok=True)


def _safe_year(x):
    from pandas import isna  # type: ignore

    try:
        if isna(x):
            return None
        s = str(x)
        if len(s) >= 4 and s[:4].isdigit():
            return int(s[:4])
        return datetime.fromisoformat(s).year
    except Exception:
        return None


def _scatter(ax, df, x, y, color=None, xlabel=None, ylabel=None, title=None, plt=None):
    c = df[color] if color and color in df.columns else None
    sc = ax.scatter(df[x], df[y], c=c, cmap="viridis", alpha=0.8, edgecolor="none")
    ax.set_xlabel(xlabel or x)
    ax.set_ylabel(ylabel or y)
    if title:
        ax.set_title(title)
    if c is not None and plt is not None:
        cb = plt.colorbar(sc, ax=ax)
        cb.set_label(color)
    ax.grid(True, linestyle=":", linewidth=0.5, alpha=0.6)


def handle_plot_scaling(args):
    """
    Generate simple scatter plots for exploit rate vs coding ability and a
    few supporting scatters, from a per-model summary CSV.

    Expected CSV columns:
      model_id, family, provider, params, log_params, launch_date,
      coding_ability_composite, EPR_insecure, secure_pass_rate, avg_output_tokens,
      n_tasks, n_runs
    """
    pd, plt = _safe_imports()

    summary_csv = args.summary if getattr(args, "summary", None) else "generated_metrics/model_summary.csv"
    if not os.path.exists(summary_csv):
        raise FileNotFoundError(f"Summary CSV not found: {summary_csv}")

    df = pd.read_csv(summary_csv)

    # Hygiene / derived columns
    if "log_params" not in df.columns and "params" in df.columns:
        import numpy as np

        df["log_params"] = np.log(df["params"].astype(float))
    if "year" not in df.columns and "launch_date" in df.columns:
        df["year"] = df["launch_date"].apply(_safe_year)

    outdir = args.out or os.path.dirname(os.path.abspath(summary_csv))
    _ensure_outdir(outdir)

    # Plot 1: EPR vs coding ability composite, colored by log_params
    fig, ax = plt.subplots(figsize=(7, 5))
    _scatter(
        ax,
        df.dropna(subset=["coding_ability_composite", "EPR_insecure"]),
        x="coding_ability_composite",
        y="EPR_insecure",
        color="log_params" if "log_params" in df.columns else None,
        xlabel="Coding Ability (composite)",
        ylabel="Exploit Rate (EPR_insecure)",
        title="Exploit vs Coding Ability",
        plt=plt,
    )
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "exploit_vs_coding.png"), dpi=200)
    plt.close(fig)

    # Plot 2: EPR vs log_params
    if "log_params" in df.columns:
        fig, ax = plt.subplots(figsize=(7, 5))
        _scatter(
            ax,
            df.dropna(subset=["log_params", "EPR_insecure"]),
            x="log_params",
            y="EPR_insecure",
            xlabel="log(Parameters)",
            ylabel="Exploit Rate (EPR_insecure)",
            title="Exploit vs Model Size",
            plt=plt,
        )
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, "exploit_vs_params.png"), dpi=200)
        plt.close(fig)

    # Plot 3: EPR vs avg_output_tokens
    if "avg_output_tokens" in df.columns:
        fig, ax = plt.subplots(figsize=(7, 5))
        _scatter(
            ax,
            df.dropna(subset=["avg_output_tokens", "EPR_insecure"]),
            x="avg_output_tokens",
            y="EPR_insecure",
            xlabel="Avg Output Tokens",
            ylabel="Exploit Rate (EPR_insecure)",
            title="Exploit vs Output Length",
            plt=plt,
        )
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, "exploit_vs_tokens.png"), dpi=200)
        plt.close(fig)

    # Plot 4: EPR vs launch year
    if "year" in df.columns:
        fig, ax = plt.subplots(figsize=(7, 5))
        _scatter(
            ax,
            df.dropna(subset=["year", "EPR_insecure"]),
            x="year",
            y="EPR_insecure",
            xlabel="Launch Year",
            ylabel="Exploit Rate (EPR_insecure)",
            title="Exploit vs Launch Year",
            plt=plt,
        )
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, "exploit_vs_launch.png"), dpi=200)
        plt.close(fig)

    print(f"Wrote plots to: {outdir}")

