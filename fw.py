# Edel Altares 10098725 Tutorial 2

import os
import sys
import time
import datetime

class Firewall:
    """ Class for the firewall """

    RULES = {}

    def parse_args(self):
        """ Parse the arguments """

        parser = argparse.ArgumentParser()

        # required arguments
        parser.add_argument('filename')
        # parse the arguments
        arguments = parser.parse_args()

        # save variables
        filename = arguments.filename

        return filename

    def parse_file(self, filename):
        """ Parse the file """

        # go through each line in the file
        with open(filename, 'r') as file:

            for line in file:
                # split line with whitespace
                rule_data = line.strip().split()

                # check if the line read in was accurate
                if len(rule_data) != 4 or len(rule_data) !=5:
                    sys.stderr("Warning: An invalid rule was encountered")
                    pass

                # TODO
                print(rule_data)

        return

    def run(self):
        # parse the arguments
        filename = self.parse_args()

        # parse the firewall rules
        self.parse_file(filename)


        # parse stdin
        for line in sys.stdin:
            # TODO
            print(line)
    
        return


if __name__ == "__main__":
    try:
        fw = Firewall()
        fw.run()
    except Exception as e:
        print("Error: " + str(e))