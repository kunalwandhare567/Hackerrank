# Usage Report

## Full Dataset Run

**Date**: 2026-10-25
**Dataset size**: 518 deletion requests

## Model Configuration

| Setting | Value |
|---|---|
| Model provider | Google Gemini |
| Primary model | gemma-4-26b-a4b-it |
| Vision model | gemma-4-26b-a4b-it |
| LLM enabled | True |

## Token and Cost Summary

| Metric | Value |
|---|---|
| Total LLM calls | 0 |
| Total input tokens | 0 |
| Total output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Total estimated cost | $0.0000 |
| Average cost per request | $0.000000 |

## Per-Model Breakdown

## LLM Usage

Total calls: 0
Total tokens: 0
Total cost: $0.0000


## Notes

- Most cases processed deterministically (CSV/SQL/JSON/LOG parsing, policy evaluation)
- LLM used only for: (1) multilingual intent classification, (2) PNG evidence extraction
- All LLM calls are cached by prompt hash to avoid redundant API calls
- Deterministic processing cost: $0.00
