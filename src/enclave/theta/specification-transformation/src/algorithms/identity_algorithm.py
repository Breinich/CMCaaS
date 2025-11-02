from typing import List

from algorithms.transformation_algorithm import TransformationAlgorithm
from data_types import SpecificationPair, Program, Specification


class IdentityAlgorithm(TransformationAlgorithm):
    def __init__(self):
        super().__init__()

    def supported_specifications(self) -> List[SpecificationPair]:
        return [
            SpecificationPair(Specification.reachability, Specification.reachability)
        ]

    def transform(
        self, program: Program, specification_pair: SpecificationPair
    ) -> List[Program]:
        if specification_pair.from_specification != specification_pair.to_specification:
            raise ValueError(
                f"The identity algorithm can only transform a program from the same specification to the same specification."
            )
        return [program]
