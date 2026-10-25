# Token Usage and Cost Report

## Final full-dataset run

- Dataset: `dataset/deletion_requests.csv`
- Requests processed: 518
- Model provider: none
- Model name: none
- External LLM/VLM calls: 0
- Input tokens: 0
- Output tokens: 0
- Total model tokens: 0
- Average model tokens per request: 0
- Estimated model cost: $0.00 total; $0.00 per request

The packaged implementation uses deterministic Python processing and does not invoke a model API. These figures refer to model API usage during the final run, not tokens used during development in ChatGPT or another coding assistant. Python CPU time and any optional OCR processing are not model token usage.

## Reproduction

```bash
python code/main.py --dataset ./dataset --requests deletion_requests.csv --output ./output.csv
```

The command prints the number of rows written and a status distribution. Do not interpret the distribution as accuracy: hidden canonical answers are unavailable, and the public sample is the only supplied labeled evaluation set.
