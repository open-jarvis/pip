#
# Copyright (c) 2020 by Philipp Scheer. All Rights Reserved.
#

import os
import sys
import re
from jarvis import Colors


class SetupTools:
    @staticmethod
    def do_action(print_str, shell_command, show_output=True, on_fail="failed!", on_success="done!", exit_on_fail=True):
        print(f" + {shell_command}")

        if not show_output:
            shell_command += " &> /dev/null"

        if not os.system(shell_command) == 0:
            print(f"{print_str}... {Colors.RED}{on_fail}{Colors.END}")
            if exit_on_fail:
                exit(1)
            return False
        else:
            print(f"{print_str}... {Colors.GREEN}{on_success}{Colors.END}")
            return True

    @staticmethod
    def regex_replace_in_file(file_path, from_regex, to_string):
        contents = None
        with open(file_path, "r") as f:
            contents = f.read()

        if contents is None:
            return False

        new_contents = re.sub(from_regex, to_string, contents, flags=re.M)

        with open(file_path, "w") as f:
            f.write(new_contents)

        return True

    @staticmethod
    def is_root():
        return os.geteuid() == 0

    @staticmethod
    def get_python_version():
        # (2, 5, 2, 'final', 0)
        return sys.version_info[0]  # returns 2 or 3

    @staticmethod
    def check_python_version(version):
        if SetupTools.get_python_version() != version:
            print(f"You need to run this script with python{version}")
            exit(1)

    @staticmethod
    def check_root():
        if not SetupTools.is_root():
            print("You need to be root!")
            exit(1)

    @staticmethod
    def get_default_installation_dir(default_dir):
        if input(f"The default Jarvis installation directory is {Colors.BLUE}{default_dir}{Colors.END}. Is this okay? [y] ") not in ["y", "Y", "z", "Z", "", "\n"]:
            return input("Enter a new installation directory (absolute path): ")
        return default_dir

    @staticmethod
    def get_default_user(default_user):
        # check for user
        if input(f"Your linux username is {Colors.BLUE}{default_user}{Colors.END}. Is this correct? [y] ") not in ["y", "Y", "z", "Z", "", "\n"]:
            return input("Enter your linux username: ")
        return default_user
