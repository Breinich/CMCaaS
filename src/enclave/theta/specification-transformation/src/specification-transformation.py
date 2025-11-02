#!/usr/bin/env python3

__version__ = "0.0.1"

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).absolute().parent.parent))

import argparse
import logging
import os
import sys

from algorithms.identity_algorithm import IdentityAlgorithm
from algorithms.instrumentation_operator import InstrumentationOperator
from data_types import SpecificationPair, Program, DataModel, Specification
from utils import setup_logging


def arguments_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--version",
        action="version",
        version="{}".format(__version__),
    )

    parser.add_argument(
        "--from-property",
        required=False,
        help="The property from which the program should be transformed.",
        metavar="FROM-PROPERTY",
    )

    parser.add_argument(
        "--to-property",
        required=False,
        help="The property to which the program should be transformed.",
        metavar="TO-PROPERTY",
    )

    parser.add_argument(
        "program",
        help="The program to be transformed.",
        metavar="PROGRAM",
    )

    parser.add_argument(
        "--data-model",
        help="The data-model.",
        choices=["ILP32", "LP64"],
        default="LP64",
        metavar="DATA_MODEL",
    )

    parser.add_argument(
        "--log-level",
        default="warning",
        choices=["critical", "error", "warning", "info", "debug"],
        help="Desired verbosity of logging output. "
        "Only log messages at or above the specified level are displayed.",
        metavar="LOGLEVEL",
    )

    parser.add_argument(
        "--algorithm",
        required=True,
        help="The algorithm to be used for the transformation.",
        metavar="ALGORITHM",
        choices=[IdentityAlgorithm.__name__, InstrumentationOperator.__name__],
        default="",
    )

    parser.add_argument(
        "--output-dir",
        required=False,
        help="The output directory.",
        default="output",
        metavar="OUTPUT_DIR",
    )

    parser.add_argument(
        "--output-name",
        required=False,
        help="The output file name.",
        default="transformed_program.c",
    )

    return parser


def process_args(args):
    args.from_property = Specification.from_string(args.from_property)
    args.to_property = Specification.from_string(args.to_property)

    if args.algorithm == IdentityAlgorithm.__name__:
        args.algorithm = IdentityAlgorithm()
    elif args.algorithm == InstrumentationOperator.__name__:
        args.algorithm = InstrumentationOperator()
    else:
        raise ValueError(f"Algorithm {args.algorithm} does not exist.")

    if (
        SpecificationPair(args.from_property, args.to_property)
        not in args.algorithm.supported_specifications()
    ):
        raise ValueError(
            f"The algorithm {args.algorithm} does not support the "
            f"transformation from {args.from_property} to {args.to_property}."
        )

    args.data_model = DataModel.from_string(args.data_model)

    args.program = Program.from_file(args.program, data_model=args.data_model)

    if args.log_level == "debug":
        args.log_level = logging.DEBUG
    elif args.log_level == "info":
        args.log_level = logging.INFO
    elif args.log_level == "warning":
        args.log_level = logging.WARNING
    elif args.log_level == "error":
        args.log_level = logging.ERROR
    elif args.log_level == "critical":
        args.log_level = logging.CRITICAL
    else:
        raise ValueError(f"Unknown log level {args.log_level}.")

    args.output_dir = Path(args.output_dir)

    return args


def main(argv):
    parser = arguments_parser()
    args = parser.parse_args(argv)

    args = process_args(args)

    setup_logging(args.log_level)

    logging.info(
        f"Transforming program {args.program} from {args.from_property} to "
        f"{args.to_property} using algorithm {args.algorithm}."
    )

    transformed_programs = args.algorithm.transform(
        args.program, SpecificationPair(args.from_property, args.to_property)
    )

    os.makedirs(args.output_dir, exist_ok=True)
    for i, transformed_program in enumerate(transformed_programs):
        transformed_program.dump(args.output_dir / args.output_name)

    return


if __name__ == "__main__":
    main(sys.argv[1:])
