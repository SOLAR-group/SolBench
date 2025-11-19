#!/usr/bin/env python3
"""
Statistical tests for questionnaire data:
- Chi-square tests for categorical associations
- Spearman rank correlations for ordinal relationships

Reads a CSV (exported from the questionnaire).
"""

import pandas as pd
from scipy.stats import chi2_contingency, spearmanr
import argparse

def run_chi_square(df, col1, col2):
    table = pd.crosstab(df[col1], df[col2])
    chi2, p, dof, exp = chi2_contingency(table)
    print(f"\n=== Chi-square Test: {col1} × {col2} ===")
    print("Chi2:", round(chi2, 4))
    print("p-value:", round(p, 4))
    print("Degrees of freedom:", dof)
    return chi2, p

def run_spearman(df, col1, col2):
    # Drop rows with NaN
    clean = df[[col1, col2]].dropna()
    rho, p = spearmanr(clean[col1], clean[col2])
    print(f"\n=== Spearman Correlation: {col1} ↔ {col2} ===")
    print("Spearman rho:", round(rho, 4))
    print("p-value:", round(p, 4))
    return rho, p

def main(csv_path):
    df = pd.read_csv(csv_path)

    print("=== Loaded Questionnaire Sample ===")
    print(df.head())
    
    # Example χ² test: Job title × Documentation usage frequency
    run_chi_square(df, 
                   "JobTitle", 
                   "DocsFrequency")

    # Example Spearman: Programming experience × Documentation usage frequency
    run_spearman(df, 
                 "ProgrammingExperienceOrdinal", 
                 "DocsFrequencyOrdinal")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run questionnaire statistical tests.")
    parser.add_argument("csv", help="Path to the questionnaire CSV sample")
    args = parser.parse_args()

    main(args.csv)
