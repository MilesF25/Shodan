import deep_analysis
import report_gen
import questionary
from pathlib import Path
import os
from InquirerPy import inquirer
import json


def main():
    """The entire flow of the program."""

    print("Welcom to the Shodan program, would you like to scan or generate a report?")
    choice = questionary.select(
        "What would you like to do", choices=["Scan", "Report"]
    ).ask()

    if choice == "Scan":
        deep_analysis.run_scan()
        print("Finished scan.")
    elif choice == "Report":
        # empty file to store json files for selection
        file_list = []
        print("Pick a file to generate a report from: \n")

        # this gets all the json files in the current directory, which is where the scans are saved
        current_directory = os.getcwd()
        for file in Path(current_directory).glob("*.json"):
            file_list.append(file.name)

        if file_list == []:
            print(
                "No json files found in the current directory. Please run a scan first."
            )
            return

        # Dispalys the file list
        file_choice = questionary.select("Pick a file:", choices=file_list).ask()
        # we are ASSUMING THE FILE IS IN THE SAME DIRECTORY AS THE PROGRAM
        path = os.path.join(current_directory, file_choice)
        with open(path) as f:
            host_data = json.load(f)

        selected_host = select_host(host_data)
        # calls report gen combined function
        print(f"1 {selected_host}")
        report_gen.combined(selected_host)
        print("Finished generating report.")

    else:
        print("Invalid choice.")


# gpt did


def select_host(
    data, sort_by="score", display_fields=("ip", "product", "score"), page_size=10
):
    """
    Display a scrollable terminal menu to select a host from a list of dicts.

    Args:
        data (list): List of dicts, each representing a host.
        sort_by (str): Field to sort by (e.g. 'score').
        display_fields (tuple): Fields to show in the menu (e.g. 'ip', 'product', 'score').
        page_size (int): Number of entries to show at once.

    Returns:
        dict: The selected host dictionary, or None if cancelled.
    """
    # Sort the data by the specified field
    sorted_data = sorted(data, key=lambda x: x.get(sort_by, 0), reverse=True)

    # Format display entries
    choices = []
    for idx, item in enumerate(sorted_data):
        values = [str(item.get(field, "N/A")) for field in display_fields]
        display = " | ".join(values)
        choices.append({"name": display, "value": idx})

    print("IP | Product | CVE Score")
    # Show interactive selection menu
    selected_index = inquirer.select(
        message="Select a host:",
        choices=choices,
        cycle=True,
        pointer=">",
    ).execute()

    # Handle cancellation
    if selected_index is None:
        print("Selection cancelled.")
        return None

    return sorted_data[selected_index]


main()


# key_use = questionary.select(
#     "do you have a google api key set up in your environment variables?",
#     choices=["Yes", "No"],
# ).ask()

# if key_use == "No":
#     print("You need a google api key to use this feature. Using no key")

# else:
#     api_key = input("Enter your google api key: ").strip()
# TODO
# need to come back and fix this, will just work on regular flow for now
