"""Runs every experiment in order. An error in one stops the run."""

from experiments import (
    common,
    exp1_scaling,
    exp2_degree,
    exp3_batch,
    exp4_secrecy,
    exp5_collusion,
    exp6_forgery,
    exp7_leaked_key,
)

EXPERIMENTS = (
    common,
    exp1_scaling,
    exp2_degree,
    exp3_batch,
    exp4_secrecy,
    exp5_collusion,
    exp6_forgery,
    exp7_leaked_key,
)


def main() -> None:
    for experiment in EXPERIMENTS:
        print(f"=== {experiment.__name__} ===", flush=True)
        experiment.main()


if __name__ == "__main__":
    main()
