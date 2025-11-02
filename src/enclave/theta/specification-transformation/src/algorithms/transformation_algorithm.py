from abc import ABC, abstractmethod
from typing import List

from src.data_types import SpecificationPair, Program


class TransformationAlgorithm(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def supported_specifications(self) -> List[SpecificationPair]:
        raise NotImplementedError(
            f"The function {self.supported_specifications.__name__} is not implemented for {self.__class__.__name__}"
        )

    @abstractmethod
    def transform(
        self, program: Program, specification_pair: SpecificationPair
    ) -> List[Program]:
        raise NotImplementedError(
            f"The function {self.transform.__name__} is not implemented for {self.__class__.__name__}"
        )
