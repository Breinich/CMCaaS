from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Specification(Enum):
    reachability = 1
    overflow = 2
    termination = 3

    @staticmethod
    def from_string(value: str):
        value = value.strip().lower()
        if value == "reachability":
            return Specification.reachability
        elif value == "termination":
            return Specification.termination
        elif value == "no-overflow":
            return Specification.overflow
        else:
            raise ValueError(f"Unknown specification {value}.")

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        return isinstance(other, Specification) and self.value == other.value


@dataclass
class SpecificationPair:
    from_specification: Specification
    to_specification: Specification

    def __hash__(self):
        return hash((self.from_specification, self.to_specification))

    def __eq__(self, other):
        return (
            isinstance(other, SpecificationPair)
            and self.from_specification == other.from_specification
            and self.to_specification == other.to_specification
        )


class DataModel(Enum):
    BIT_32 = "ILP32"
    BIT_64 = "LP64"

    @staticmethod
    def from_string(value: str):
        if value == "ILP32":
            return DataModel.BIT_32
        elif value == "LP64":
            return DataModel.BIT_64
        else:
            raise ValueError(f"Unknown data model {value}.")

    def __str__(self):
        return self.value


class Program:
    def __init__(self, program_path: str, program_code: str, data_model: DataModel = DataModel.BIT_32):
        self.program_path = program_path
        self.program_code = program_code
        self.data_model = data_model

    def dump(self, path: Path):
        with open(path, mode="w+") as append:
            append.write(self.program_code)

    @staticmethod
    def from_file(path: Path, data_model: DataModel = DataModel.BIT_32):
        with open(path, mode="r") as prg:
            return Program(path, prg.read(), data_model)
