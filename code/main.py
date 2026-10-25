"""
main.py — Ghost Data Still Exists: Deletion Audit Agent
HackerRank Orchestrate October 2026

Usage:
    python code/main.py

Reads from:  dataset/
Writes to:   output.csv (repo root)
             code/evaluation/usage_report.md
"""
import logging
import sys
import time
from pathlib import Path

# Add code/ to path so `from src.xxx import` works
sys.path.insert(0, str(Path(__file__).parent))

from src.config import OUTPUT_PATH
from src.pipeline import DeletionAuditPipeline


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
        datefmt='%H:%M:%S',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('agent_run.log', encoding='utf-8'),
        ]
    )


def main():
    setup_logging()
    logger = logging.getLogger('main')

    logger.info("=" * 60)
    logger.info("  Ghost Data Still Exists — Deletion Audit Agent")
    logger.info("  HackerRank Orchestrate October 2026")
    logger.info("=" * 60)

    t0 = time.time()

    # Build and run pipeline
    pipeline = DeletionAuditPipeline()
    results = pipeline.run()

    # Write output.csv
    pipeline.write_output(results, OUTPUT_PATH)

    # Write usage report
    usage_path = Path(__file__).parent / 'evaluation' / 'usage_report.md'
    pipeline.write_usage_report(usage_path)

    elapsed = time.time() - t0
    total_complete   = sum(1 for r in results if r['deletion_status'] == 'COMPLETE')
    total_incomplete = sum(1 for r in results if r['deletion_status'] == 'INCOMPLETE')
    total_na         = sum(1 for r in results if r['deletion_status'] == 'NOT_APPLICABLE')

    logger.info("=" * 60)
    logger.info(f"  Results: {len(results)} total cases in {elapsed:.1f}s")
    logger.info(f"  COMPLETE:       {total_complete}")
    logger.info(f"  INCOMPLETE:     {total_incomplete}")
    logger.info(f"  NOT_APPLICABLE: {total_na}")
    logger.info(f"  Token usage:    {pipeline.usage.total_tokens:,}")
    logger.info(f"  Est. cost:      ${pipeline.usage.total_cost:.4f}")
    logger.info(f"  Output:         {OUTPUT_PATH}")
    logger.info("=" * 60)

    # Quick sanity check
    import csv, json
    with open(OUTPUT_PATH, encoding='utf-8') as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 518, f"ERROR: Expected 518 rows, got {len(rows)}"
    for row in rows:
        assert row['deletion_status'] in ('COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE')
        steps = json.loads(row['steps_json'])
        assert isinstance(steps, list)

    logger.info("✅ Output validation passed — ready for submission!")


if __name__ == '__main__':
    main()
