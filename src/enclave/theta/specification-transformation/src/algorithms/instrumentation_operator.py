import subprocess, os
from dataclasses import dataclass
import sys
from typing import Dict, List, Tuple

from algorithms.transformation_algorithm import TransformationAlgorithm
from data_types import SpecificationPair, Program, Specification


@dataclass
class NormalLoopInfo:
    """Represents a container for normal loop information(for, while, do-while, and goto loop).

    Attributes:
        loop_location: line number where the loop is located.
        live_variables_and_types: A mapping from variables names used, but not declared, in a loop to their types.
    """

    loop_location: int
    live_variables_and_types: Dict[str, str]

    def __iter__(self):
        yield self.loop_location
        yield self.live_variables_and_types


@dataclass
class RecursionInfo:
    """Represents a container for recursion information.

    Attributes:
        function_name: the name of the function
        location_of_definition: the line number where the function is defined
        location_of_recursive_calls: a set of line numbers where the recursive calls occur
        parameters: the function's parameters(type + name)

    """

    function_name: str
    location_of_definition: int
    location_of_recursive_calls: set[int]
    parameters: List[Tuple[str, str]]

    def __iter__(self):
        yield self.function_name
        yield self.location_of_definition
        yield self.location_of_recursive_calls
        yield self.parameters


class InstrumentationOperator(TransformationAlgorithm):
    def __init__(self):
        super().__init__()

    def supported_specifications(self) -> List[SpecificationPair]:
        return [
            SpecificationPair(Specification.termination, Specification.reachability),
            SpecificationPair(Specification.overflow, Specification.reachability)
        ]

    def transform(
        self, program: Program, specification_pair: SpecificationPair) -> List[Program]:
        """Instrument program"""
        if (
            (specification_pair.from_specification != Specification.termination
            and specification_pair.from_specification != Specification.overflow)
            or specification_pair.to_specification != Specification.reachability
        ):
            raise ValueError(
                f"The instrumentation operator works only from {Specification.termination.name} or {Specification.overflow.name} to {Specification.reachability.name}."
            )

        if specification_pair.from_specification == Specification.termination and self.__has_unsupported_types_or_loop_structures(program.program_code):
            raise Exception(
                f"The program {program.program_path} has unsupported types or loop structures"
            )
        
        program = self.__format(program)
        self.__sequentialization_operator(program.program_path, specification_pair)
        all_edge_info = self.__extract_edge_info("output/newEdgesInfo.txt", specification_pair)
        instrumented_code = self.__get_instrumented_code(program, all_edge_info)
        program.program_code = instrumented_code

        return [program]

    def __has_unsupported_types_or_loop_structures(self, program_code):
        return "[" in program_code or "struct" in program_code

    def __format(self, program) -> str:
        """Formats program while preserving a large column limit to keep the
        loop head of every loop on a single line."""
        dir_for_formatted_files = "formatted_files"
        path_for_formatted_file = (
            f"formatted_files/{program.program_path.split('/')[-1]}"
        )
        os.makedirs(dir_for_formatted_files, exist_ok=True)
        with open(path_for_formatted_file, "w") as file_w:
            file_w.write(program.program_code)

        try:
            subprocess.run(
                [
                    'clang-format',
                    '-style={"ColumnLimit": 10000}',
                    '-i',
                    path_for_formatted_file,
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            raise Exception(f"Formatting of program {program.program_path} failed!")
        else:
            return Program.from_file(path_for_formatted_file)

    def __sequentialization_operator(self, program_path, specification_pair: SpecificationPair):
        """Generate CFA information using CPAchecker, which implicitly output it to a file."""
        property = "TERMINATION"
        if specification_pair.from_specification == Specification.overflow:
            property = "NOOVERFLOW"
        try:
            subprocess.run(
                [   "java", "-cp",
                    f"{os.path.dirname(os.path.dirname(os.path.dirname(__file__)))}/cpachecker/runtime/*:{os.path.dirname(os.path.dirname(os.path.dirname(__file__)))}/cpachecker/cpachecker.jar",
                    "org.sosy_lab.cpachecker.cmdline.CPAMain",
                    "--preprocess",
                    "--option",
                    "analysis.algorithm.instrumentation.instrumentationOperator=true",
                    "--option",
                    "cfa.simplifyCfa=false",
                    "--option",
                    "cfa.simplifyConstExpressions=false",
                    "--option",
                    "instrumentation.instrumentationProperty=" + property,
                    program_path,
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            raise Exception(
                "The creation of file newEdgeInfo.txt by CPAChecker failed!"
            )

    def __extract_edge_info(
        self, loop_infos_file_path, specification_pair
    ) -> List[Tuple[int, str]]:
        """Extract loop information from the file created by CPAchecker."""
        seq_operator_info = []

        with open(loop_infos_file_path, "r") as loop_infos_file:
            edges_info_lines = loop_infos_file.readlines()

            if edges_info_lines == []:
                sys.exit("The transformed CFA does not contain any new edges !")

            for edge_info in edges_info_lines:
                edge_info_list = edge_info.split("|||")
                line_number, new_operation = edge_info_list[0], edge_info_list[1]
                seq_operator_info.append((int(line_number), new_operation))
        return seq_operator_info

    def __get_instrumented_code(
        self,
        program: Program,
        edges_info: List[Tuple[int, str]],
    ) -> str:
        """Instrument program using provided loop information."""
        num_of_lines_added = 0
        numbered_program_lines = []
        program_code = program.program_code
        for program_line in program_code.split("\n"):
            numbered_program_lines.append(program_line)

        # Insert definition of function __VERIFIER_assert() at the top of the program
        if "void __VERIFIER_assert" not in program_code:
            if "extern void __assert_fail" not in program_code:
                numbered_program_lines.insert(
                    0,
                    "extern void __assert_fail(const char *, const char *, unsigned int, const char *) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));"
                )
                num_of_lines_added += 1
            if "void reach_error()" not in program_code:
                reach_error_line_num = 1
                numbered_program_lines.insert(
                    num_of_lines_added,
                    f"void reach_error() {{\n    __assert_fail(\"0\", \"{program.program_path.split('/')[-1][:-1]}c\", 3, \"reach_error\");\n}}"
                )
                num_of_lines_added += 1
            else:
                reach_error_line_num = 0
                while "void reach_error()" not in numbered_program_lines[reach_error_line_num]:
                    reach_error_line_num += 1
                reach_error_line_num += 1
            if "void __VERIFIER_assert" not in program_code:
                numbered_program_lines.insert(
                    num_of_lines_added,
                    "void __VERIFIER_assert(int cond) {\n    if (!(cond)) {\n        ERROR: reach_error();\n    }\n    return;\n}"
                )
                num_of_lines_added += 1
        
        # Instrumentation Operator
        edges_info = sorted(edges_info)
        for (instr_line_number, operation) in edges_info:
            for line_number, program_line in enumerate(numbered_program_lines.copy(), start=1):
                if line_number == (instr_line_number + num_of_lines_added):
                    if any(x in numbered_program_lines[line_number-1] for x in ('while', 'if', 'for')) and "{" not in numbered_program_lines[line_number-1]:
                        numbered_program_lines[line_number-1] += "{"
                        numbered_program_lines[line_number] += "}"
                    # Insert operation
                    numbered_program_lines.insert(
                        line_number - 1,
                        operation
                    )
                    num_of_lines_added += 1
                    break

        return "\n".join(numbered_program_lines)
