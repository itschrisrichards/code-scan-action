import argparse
import os
import requests
from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple


##
#
##
def get_response_from_api(content, url):

    # Get repo and user info from Github
    # basename `git rev-parse --show-toplevel`
# git config --list
# user.email, user.name, remote.origin.url
# git config user.email

    payload = {"data": content}

    # TODO: need some sort of auth header
    headers = {"Content-Type": "application/json"}

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


##
#
##
@dataclass
class PiiResult:
    filename: str
    line: int
    start_index: int
    end_index: int
    entity_length: int
    entity_type: str,
    value: str


##
#
##
def check_for_pii(filename: str, url: str, enabled_entity_list: List[str], ignore_entities: List[str]) -> List[PiiResult]:
    # Open text file in read mode
    source_file = open(filename, "r")

    # Read whole file to a string
    data = source_file.read()

    # Close file
    source_file.close()

    # Call Louper API with code contents
    api_pii_results = get_response_from_api(data, url)

    # Assemble result array based on include/ignore preferences
    pii_results: List[PiiResult] = []
    for entity in api_pii_results["data"]:
        if entity["entity"]["stub"] not in ignore_entities:
            pii_results.append(
                PiiResult(
                    filename,
                    100,  # TODO: figure out line numbering
                    entity["start_offset"],
                    entity["end_offset"],
                    entity["end_offset"] - entity["start_offset"],
                    entity["entity"]["stub"],
                    entity["entity"]["value_remove_me"]
                )
            )

    return pii_results


##
#
##
def main():
    parser = argparse.ArgumentParser(
        prog="LouperAI-CodeScanHook",
        description="This hook checks if stage commit files have senstive data",
    )
    parser.add_argument("filenames", nargs="*")
    parser.add_argument("--url", type=str, required=True)
    parser.add_argument(
        "--enabled-entities",
        type=str,
        nargs="+",
        default=[
            "PASSWORD",
            "BANK_ACCOUNT",
            "CREDIT_CARD",
            "CREDIT_CARD_EXPIRATION",
            "CVV",
            "ROUTING_NUMBER",
        ],
    )
    parser.add_argument("--ignore-entities", type=str)
    args = parser.parse_args()

    # To start we should just enable all by default, provide a bigger list of defaults above
    enabled_entity_list = [item.upper() for item in args.enabled_entities]

    # API will return all found entities, we probably want to ignore a few types (like URL and EMAIL)
    ignore_entities = (
        [ignored.upper() for ignored in args.ignore_entities.split(",")] if args.ignore_entities else []
    )

    # Check for Sensitive Data in all relevant files
    try:
        pii_results = [
            result
            for filename in args.filenames
            for result in check_for_pii(
                os.path.abspath(filename),
                args.url,
                enabled_entity_list,
                ignore_entities,
            )
        ]
    except RuntimeError as e:
        print(e)
        print(
            "If you get this message when running `pre-commit run -a` make sure to scan the files manually for sensitive data instead of using this hook."
        )
        return 2

    # Raise results to pre-commit or CLI
    if pii_results:
        for result in pii_results:
            print(
                f"""Found sensitive data [{result.entity_type}]:[{result.value_remove_me}] - File "{result.filename}", line {result.line}, at index {result.start_index}:{result.end_index}"""
            )

        print("Review the above problems before committing the changes.")
        return 1
    else:
        print(f"Scanned {len(args.filenames)} file(s) and found no sensitive data")
        return 0

    return 0


##
#
##
if __name__ == "__main__":
    main()
