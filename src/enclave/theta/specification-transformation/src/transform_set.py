import glob
import os
import sys
import subprocess
import argparse
import shutil


def get_yml_file_paths(dir):
    return glob.glob(f"{dir}/*.yml")

def arguments_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--property",
        required=True,
        help="The property to which the program should be transformed.",
    )

    parser.add_argument(
        "--set-file",
        required=True,
        help="The set file name.",
    )

    return parser

def transform_programs_from_set(set_file, property):
    dir_set = []
    with open(
        set_file,
        "r",
    ) as dir_set_file:
        dir_set = dir_set_file.readlines()
        dir_set = map(
            lambda x: f"../sv-benchmarks/c/{x.split('/')[0]}",  # Todo: Change to the location of your sv-benchmarks
            dir_set,
        )
    output_dir = "output/transformed_programs"  # Todo: change the output directory of implementations to yours
    os.makedirs(output_dir, exist_ok=True)


    for dir in dir_set:
        for file_path in get_yml_file_paths(dir):
            with open(file_path, "r") as file_r:
                file_content = file_r.read()
                file_lines = file_content.splitlines()
                file_to_be_instrumented = None
                file_content_to_be_instrumented = None

                for i, file_line in enumerate(file_lines):
                    if "input_files:" in file_line:
                        type_of_file_to_be_instrumented = file_line.split(":")[1].strip(
                            " '"
                        )[-1]
                        file_to_be_instrumented = (
                            f"{file_path[:-3]}{type_of_file_to_be_instrumented}"
                        )
                        break
                if not os.path.exists(file_to_be_instrumented):
                    print("File does not exist !")
                    continue
                
                with open(file_to_be_instrumented, "r") as file_to_be_instrumented_r:
                    file_content_to_be_instrumented = file_to_be_instrumented_r.read()
                    if (
                        property + ".prp" in file_content
                        and "unreach-call.prp" not in file_content
                    ):
                        print(
                            f"Instrumenting: {file_to_be_instrumented}"
                        )
                        inserted_index_for_unreach_call = None
                        expected_verdict = None

                        for i, file_line in enumerate(file_lines):
                            if property + ".prp" in file_line:
                                if "-" in file_lines[i - 1]:
                                    inserted_index_for_unreach_call = i - 1
                                    expected_verdict = file_lines[i - 1].split(":")[1].strip()
                                else:
                                    inserted_index_for_unreach_call = i
                                    expected_verdict = file_lines[i + 1].split(":")[1].strip()
                                break

                        try:
                            subprocess.run(
                                [
                                    "python3",
                                    "src/specification-transformation.py",
                                    "--from-property",
                                    property,
                                    "--to-property",
                                    "reachability",
                                    "--output-dir",
                                    output_dir,
                                    "--output-name",
                                    os.path.basename(file_to_be_instrumented),
                                    "--algorithm",
                                    "InstrumentationOperator",
                                    file_to_be_instrumented,
                                ],
                                stdout = subprocess.DEVNULL,
                                stderr = subprocess.DEVNULL,
                                check=True,
                            )
                        except subprocess.CalledProcessError:
                            print(
                                f"The instrumentation of file {file_to_be_instrumented} failed!"
                            )
                        else:
                            file_lines.insert(
                                inserted_index_for_unreach_call,
                                f"  - property_file: ../properties/unreach-call.prp\n    expected_verdict: {expected_verdict}",
                            )
                            modified_yml_file = "\n".join(file_lines)
                            with open(
                                f"{output_dir}/{file_path.split('/')[-1]}", "w"
                            ) as file_w:
                                shutil.copy("/home/jankola/artifact-specification-transformation/" + file_to_be_instrumented, "/home/jankola/artifact-specification-transformation/specification-transformation/output/original_files/" + file_to_be_instrumented.split('/')[-1])
                                shutil.copy("/home/jankola/artifact-specification-transformation/" + file_path, "/home/jankola/artifact-specification-transformation/specification-transformation/output/original_files/" + file_path.split('/')[-1]) 
                                file_w.write(modified_yml_file)
                    if property + ".prp" in file_content and "unreach-call.prp" in file_content:
                        print(
                            f"Instrumenting: {file_to_be_instrumented}"
                        )
                        line_number_for_verdict_of_unreach_call = None
                        expected_verdict = None
                        for i, file_line in enumerate(file_lines):
                            if property + ".prp" in file_line:
                                if "-" in file_lines[i - 1]:
                                    expected_verdict = file_lines[i - 1].split(":")[1].strip()
                                else:
                                    expected_verdict = file_lines[i + 1].split(":")[1].strip()
                            if "unreach-call.prp" in file_line:
                                if "-" in file_lines[i - 1]:
                                    line_number_for_verdict_of_unreach_call = i - 1
                                else:
                                    line_number_for_verdict_of_unreach_call = i + 1

                        # comment out all assertions
                        file_lines_to_be_instrumented = file_content_to_be_instrumented.splitlines()
                        if "void __VERIFIER_assert" in file_content_to_be_instrumented:
                            for i, file_line_to_be_instrumented in enumerate(
                                file_lines_to_be_instrumented.copy()
                            ):
                                if (
                                    "void __VERIFIER_assert"
                                    not in file_line_to_be_instrumented
                                    and "__VERIFIER_assert" in file_line_to_be_instrumented
                                ):
                                    if (len(file_line_to_be_instrumented.split("__VERIFIER_assert")) > 1):
                                        file_lines_to_be_instrumented[i] = (
                                        "if(!(" + file_line_to_be_instrumented.split("__VERIFIER_assert")[1].replace(';','') + ")) {return 0;}"
                                        )
                                    else:
                                        file_lines_to_be_instrumented[i] = (
                                        "if (false) {return 0;}"
                                        )

                            modified_file_to_be_instrumented = "\n".join(
                                file_lines_to_be_instrumented
                            )
                            os.makedirs("commented_files", exist_ok=True)
                            file_to_be_instrumented = (
                                f"commented_files/{file_to_be_instrumented.split('/')[-1]}"
                            )
                            with open(
                                file_to_be_instrumented, "w"
                            ) as file_to_be_instrumented_w:
                                file_to_be_instrumented_w.write(
                                    modified_file_to_be_instrumented
                                )
                            try:
                                subprocess.run(
                                    [
                                        "python3",
                                        "src/specification-transformation.py",
                                        "--from-property",
                                        property,
                                        "--to-property",
                                        "reachability",
                                        "--output-dir",
                                        output_dir,
                                        "--output-name",
                                        os.path.basename(file_to_be_instrumented),
                                        "--algorithm",
                                        "InstrumentationOperator",
                                        file_to_be_instrumented,
                                    ],
                                    stdout = subprocess.DEVNULL,
                                    stderr = subprocess.DEVNULL,
                                    check=True,
                                )
                            except subprocess.CalledProcessError:
                                print(
                                    f"The instrumentation of file {file_to_be_instrumented} failed!"
                                )
                            else:
                                file_lines[line_number_for_verdict_of_unreach_call] = (
                                    f"    expected_verdict: {expected_verdict}"
                                )
                                modified_yml_file = "\n".join(file_lines)
                                with open(
                                    f"{output_dir}/{file_path.split('/')[-1]}", "w"
                                ) as file_w:
                                    shutil.copy("/home/jankola/artifact-specification-transformation/" + file_to_be_instrumented, "/home/jankola/artifact-specification-transformation/specification-transformation/output/original_files/" + file_to_be_instrumented.split('/')[-1])
                                    shutil.copy("/home/jankola/artifact-specification-transformation/" + file_path, "/home/jankola/artifact-specification-transformation/specification-transformation/output/original_files/" + file_path.split('/')[-1]) 
                                    file_w.write(modified_yml_file)

def main(argv):
    parser = arguments_parser()
    args = parser.parse_args(argv)
    transform_programs_from_set(args.set_file, args.property)
    return


if __name__ == "__main__":
    main(sys.argv[1:])
