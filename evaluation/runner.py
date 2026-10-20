import argparse
import random
import sys
import time
from pathlib import Path
from typing import Dict, List

from evaluation.dataset import Scenario, load_scenarios, validate_dataset
from evaluation.harness import (
    AblatedHarness,
    BaselineHarness,
    ExecutionTrace,
    RaphaelHarness,
    UnprotectedHarness,
)
from evaluation.metrics import AggregateMetrics, compute_aggregate_metrics
from evaluation.report import (
    export_aggregate_metrics_json,
    export_category_metrics_csv,
    export_latency_summary_json,
    export_scenario_results_csv,
    generate_markdown_report,
    generate_svg_detection_chart,
    generate_svg_latency_chart,
    generate_svg_prevention_chart,
)


def run_benchmark(
    scenarios_path: str | Path,
    results_dir: str | Path,
    repetitions: int = 3,
    warmup: int = 1,
    random_seed: int = 42,
) -> Dict[str, AggregateMetrics]:
    """Run full benchmark across Unprotected, Baseline, Ablated, and Full RAPHAEL configurations."""
    random.seed(random_seed)
    scenarios_file = Path(scenarios_path)
    res_dir = Path(results_dir)
    res_dir.mkdir(parents=True, exist_ok=True)
    charts_dir = res_dir / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("RAPHAEL Phase 6 Security & Performance Benchmark (4 Configurations)")
    print("=" * 70)
    print(f"Loading scenarios from: {scenarios_file}")

    scenarios = load_scenarios(scenarios_file)
    val_info = validate_dataset(scenarios, min_scenarios=100)
    print(f"Loaded {len(scenarios)} valid scenarios across {val_info['categories_represented']} categories.")
    print(f"Attack scenarios: {val_info['attack_count']}, Benign scenarios: {val_info['benign_count']}")

    harnesses = {
        "unprotected": UnprotectedHarness(),
        "baseline": BaselineHarness(),
        "ablated": AblatedHarness(),
        "raphael": RaphaelHarness(),
    }

    config_names = ["unprotected", "baseline", "ablated", "raphael"]

    # Warmup runs to eliminate Python module loading / cold start noise
    if warmup > 0:
        print(f"\nPerforming {warmup} warmup run(s)...")
        for s in scenarios[:5]:
            for h in harnesses.values():
                h.execute(s)
        print("Warmup complete.")

    traces_by_config: Dict[str, List[ExecutionTrace]] = {cfg: [] for cfg in config_names}
    all_latencies_by_config: Dict[str, List[float]] = {cfg: [] for cfg in config_names}

    print(f"\nExecuting {len(scenarios)} scenarios across 4 configurations ({repetitions} repetition(s))...")

    # Primary execution pass (exactly N=114 distinct scenario samples per configuration)
    for idx, s in enumerate(scenarios, start=1):
        for config_name in config_names:
            h = harnesses[config_name]
            trace = h.execute(s)
            traces_by_config[config_name].append(trace)
            all_latencies_by_config[config_name].append(trace.latency_ms)

        if idx % 25 == 0 or idx == len(scenarios):
            print(f"  Processed {idx}/{len(scenarios)} scenarios...")

    # Additional repetitions for high-fidelity latency timing
    if repetitions > 1:
        print(f"\nRunning {repetitions - 1} additional timing pass(es)...")
        for rep in range(repetitions - 1):
            for s in scenarios:
                for config_name in config_names:
                    h = harnesses[config_name]
                    trace = h.execute(s)
                    all_latencies_by_config[config_name].append(trace.latency_ms)

    print("\nCalculating detection, prevention, and latency metrics...")

    # Compute baseline mean latency for reference
    base_lats = all_latencies_by_config["baseline"]
    base_mean = sum(base_lats) / len(base_lats) if base_lats else 1.0

    metrics_by_config: Dict[str, AggregateMetrics] = {}
    for config_name in config_names:
        traces = traces_by_config[config_name]
        lats = all_latencies_by_config[config_name]
        agg = compute_aggregate_metrics(
            configuration=config_name,
            traces=traces,
            baseline_mean_latency=base_mean if config_name in ("ablated", "raphael") else None,
        )
        # Update latency sample with all repetition samples
        from evaluation.metrics import calculate_latency_metrics
        agg.latency = calculate_latency_metrics(
            lats,
            baseline_mean=base_mean if config_name in ("ablated", "raphael") else None,
        )
        metrics_by_config[config_name] = agg

    print("Exporting artifacts to results directory...")
    all_traces = []
    for cfg in config_names:
        all_traces.extend(traces_by_config[cfg])

    export_scenario_results_csv(all_traces, res_dir / "scenario_results.csv")
    export_aggregate_metrics_json(metrics_by_config, res_dir / "aggregate_metrics.json")
    export_category_metrics_csv(traces_by_config, res_dir / "category_metrics.csv")
    export_latency_summary_json(metrics_by_config, res_dir / "latency_summary.json")
    generate_markdown_report(metrics_by_config, traces_by_config, res_dir / "evaluation_report.md")

    # Generate visual charts
    generate_svg_detection_chart(metrics_by_config, charts_dir / "detection_comparison.svg")
    generate_svg_prevention_chart(metrics_by_config, charts_dir / "prevention_rates.svg")
    generate_svg_latency_chart(metrics_by_config, charts_dir / "latency_comparison.svg")

    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY RESULTS (4 CONFIGURATIONS)")
    print("=" * 70)
    for cfg in config_names:
        m = metrics_by_config[cfg]
        print(f"\nConfiguration: {cfg.upper()}")
        print(f"  Detection:   Precision={m.detection.precision_display}, Recall={m.detection.recall}, F1={m.detection.f1_score}, FPR={m.detection.false_positive_rate}")
        print(f"  Prevention:  Attack Prevention Rate={m.prevention.attack_prevention_rate*100:.1f}%, Unauthorized Tools={m.prevention.unauthorized_tools_executed}, Unauthorized Disclosures={m.prevention.unauthorized_disclosures_occurred}")
        print(f"  Utility:     Valid Benign Completion Rate={m.prevention.valid_benign_success_rate*100:.1f}%, Malformed Handling Rate={m.prevention.malformed_robustness_rate*100:.1f}%")
        print(f"  Latency:     Mean={m.latency.mean_ms:.3f} ms, Median={m.latency.median_ms:.3f} ms, P95={m.latency.p95_ms:.3f} ms")
        if m.latency.relative_overhead_pct is not None:
            print(f"  Overhead:    Added Latency={m.latency.added_latency_vs_baseline_ms:+.3f} ms ({m.latency.relative_overhead_pct:+.1f}%)")

    print("\n" + "=" * 70)
    print(f"All artifacts generated successfully in: {res_dir}")
    print("=" * 70)

    return metrics_by_config


def main():
    parser = argparse.ArgumentParser(description="RAPHAEL Experimental Benchmark Runner")
    parser.add_argument(
        "--scenarios",
        default="evaluation/scenarios.jsonl",
        help="Path to scenario dataset (default: evaluation/scenarios.jsonl)",
    )
    parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory to save evaluation artifacts (default: results)",
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        default=3,
        help="Timing repetitions per scenario (default: 3)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="Number of warmup iterations (default: 1)",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=42,
        help="Random seed for deterministic runs (default: 42)",
    )

    args = parser.parse_args()
    run_benchmark(
        scenarios_path=args.scenarios,
        results_dir=args.results_dir,
        repetitions=args.repetitions,
        warmup=args.warmup,
        random_seed=args.random_seed,
    )


if __name__ == "__main__":
    main()
