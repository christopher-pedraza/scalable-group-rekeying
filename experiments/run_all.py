"""Runs every experiment in order. An error in one stops the run."""

import common
import exp1_scaling
import exp2_degree
import exp3_batch
import exp4_secrecy
import exp5_collusion
import exp6_forgery
import exp7_leaked_key

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
