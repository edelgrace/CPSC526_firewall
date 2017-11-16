# Edel Altares 10098725 Tutorial 2

import os
import sys
import time
import datetime
import argparse

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

    def valid_rule(self, rule):
        """ Check if the rule is valid """
        flag = True

        if len(rule) > 5 or len(rule) < 4:
            return False


        direction = str(rule[0])
        action = str(rule[1])
        ip = str(rule[2])
        ports_og = str(rule[3])
        ports = str(rule[3]).split(",")
        established = str(rule[-1])

        # check if direction is correct
        if direction not in ("in", "out"):
            flag = False

        # check if action is correct
        if action not in ("deny", "accept", "reject"):
            flag = False

        # check if IP is correct
        if len(ip.split(".")) != 4 and ip != "*":
            flag = False
            
        # check if each port is good
        for port in ports:
            if port == "*":
                continue
            elif int(port) not in range(0,65535):
                flag = False

        # check if flag is good
        if established != ports_og and established != "established":
            flag = False

        return flag


    def parse_file(self, filename):
        """ Parse the file """

        # go through each line in the file
        with open(filename, 'r') as file:
            count = 0

            for line in file:
                # split line with whitespace
                rule_data = line.strip().split()

                # rule is not valid
                if not self.valid_rule(rule_data):
                    sys.stderr.write(str(count) + " Warning: An invalid rule was encountered\n")

                # rule is valid
                else:
                    # TODO
                    # print(rule_data)

                    count += 1

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
    fw = Firewall()
    fw.run()