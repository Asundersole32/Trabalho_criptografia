#!/usr/bin/env python3
import pandas as pd
import argparse


def format_num(x: float, decimals: int = 2) -> str:
    return f"{x:.{decimals}f}"


def main():
    parser = argparse.ArgumentParser(
        description="Print aggregate throughput from CSV using pandas."
    )
    parser.add_argument("csv_path", help="Path to the CSV file (no header).")
    args = parser.parse_args()

    # Column layout from your sample
    cols = [
        "id",
        "algo",
        "mode",
        "label",
        "op",
        "runs",
        "sizeBytes",
        "col7",
        "col8",
        "col9",
        "col10",
        "col11",
        "wallMs",
    ]

    df = pd.read_csv(args.csv_path, header=None, names=cols)

    # Convert numeric columns properly
    df["runs"] = pd.to_numeric(df["runs"], errors="coerce")
    df["sizeBytes"] = pd.to_numeric(df["sizeBytes"], errors="coerce")
    df["wallMs"] = pd.to_numeric(df["wallMs"], errors="coerce")

    # Filter to max runs (like the TS code)
    max_runs = df["runs"].max()
    df = df[df["runs"] == max_runs]

    # Preserve label order as they appear
    size_labels = df["label"].unique().tolist()

    modes_ordered = ["ECB", "CBC"]
    algos = ["AES", "Twofish", "Blowfish"]
    ops = ["encrypt", "decrypt"]

    print("\nThroughput (approx):")
    for algo in algos:
        for mode in modes_ordered:
            for op in ops:
                for label in size_labels:
                    row = df[
                        (df["algo"] == algo)
                        & (df["mode"] == mode)
                        & (df["op"] == op)
                        & (df["label"] == label)
                    ]
                    if row.empty:
                        continue
                    r = row.iloc[0]
                    total_bytes = r["sizeBytes"] * r["runs"]
                    mbps = (total_bytes / (1024 * 1024)) / (r["wallMs"])
                    print(
                        f"{algo} {mode} {op.upper()} {label} x{int(r['runs'])} → ~{format_num(mbps, 2)} MB/s"
                    )


if __name__ == "__main__":
    main()
