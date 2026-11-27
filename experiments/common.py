# TODO: Shared: Once two experiments need the same setup or result saving

"""
workload      -> generates the events (joins, leaves, rejoins)
simulator     -> applies them to a scheme and records what happened
  scheme      -> does the actual rekeying (star / lkh / tgdh)
  verifier    -> observes after each batch and judges the result
experiments   -> set all this up, run it, report results
tests         -> check that each piece of code works


verifier = Verifier()
simulator = Simulator(make_scheme("lkh", SchemeConfig(seed=1)), [verifier])
simulator.init(members)
simulator.run(batches)
print(verifier.violations)  # empty means no problems found
"""


def main() -> None:
    print("not implemented yet")


if __name__ == "__main__":
    main()
