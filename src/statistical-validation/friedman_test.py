#!/usr/bin/env python3
"""
Friedman test for comparing 11 automated analysis tools.
Reads a CSV file where each row is a tool and each column is an EH misuse category.
"""

import pandas as pd
from scipy.stats import friedmanchisquare
import argparse

def main(csv_path):
    # Load dataset
    df = pd.read_csv(csv_path)

    print("=== Loaded Tool Detection Matrix ===")
    print(df)
    print()

    # Numeric EH categories (everything except 'Tool')
    categories = [c for c in df.columns if c != "Tool"]

    # Friedman test requires one array per condition (category)
    values = [df[c].values for c in categories]

    # Run Friedman test
    stat, p = friedmanchisquare(*values)

    print("=== Friedman Test Result (All Tools) ===")
    print(f"Chi-square statistic: {stat:.4f}")
    print(f"p-value: {p:.4f}")

    if p < 0.05:
        print("Significant differences detected among tools (p < 0.05)")
    else:
        print("No significant differences detected among tools (p ≥ 0.05)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Friedman test on all tools.")
    parser.add_argument("csv", help="Path to the all-tools CSV file")
    args = parser.parse_args()

    main(args.csv)
