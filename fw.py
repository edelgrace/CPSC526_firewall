# Edel Altares 10098725 Tutorial 2

import os
import sys
import time
import datetime
import argparse

class Firewall:
    """ Class for the firewall """

    RULES = []

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


        d


    def rule_to_dict(self, rule):
        """ Convert rule to dictionary """

        direction = str(rule[0])
        action = str(rule[1])
        ip = str(rule[2])
        ports = str(rule[3]).split(",")
        established = str(rule[-1])

        # create a dict out of the the rule
        dict = {'ip': ip,
                'direction': direction,
                'ports': ports,
                'flag': established
            }

        return dict


    def parse_file(self, filename):
        """ Parse the file """

        # go through each line in the file
        with open(filename, 'r') as file:
            count = 0

            for line in file:
                # split line with whitespace
                rule_data = line.strip().split()

                # rule is valid
                if  self.valid_rule(rule_data):
                    count += 1

                    # add to rule list
                    rule = self.rule_to_dict(rule_data)
                    self.RULES.append(rule)

                # rule is not valid
                else:
                    # print(rule_data)
                    sys.stderr.write(str(count) + " Warning: An invalid rule was encountered\n")

        return


    def parse_packet(self, packet):
        """ parse packet """

        # split packet
        packet = packet.strip().split()

        direction = str(packet[0])
        ip = str(packet[1])
        port = int(packet[2])
        flag = int(packet[3])

        dict = {
            'direction': direction,
            'ip': ip,
            'port': port,
            'flag': flag    
        }

        return dict


    def check_rule(self, packet):
        """ check packet against rule """

        # go through each rule
        for rule in self.RULES:

            # check if ip is in the rule
            if self.check_ip(rule['ip'], packet['ip']):
                sys.stdout.write("DEBUG ip matches")
                
        return


    def ip_to_binary(self, ip):
        """ Convert an ip address to binary """

        ip_binary = ""

        # split into octets
        ip = ip.split(".")
        range = ip[3].split("/")
        ip[3] = range[0]

        # go through each octet
        for octet in ip:
            # convert to binary
            octet_binary = bin(int(octet))[2:]

            ip_binary += octet_binary

        # convert range to binary
        if range[0] != range[-1]:
            range = bin(int(range[1]))[2:]
        else:
            range = '0'

        # return the binary
        return (ip_binary, range)

    def check_ip(self, rule_ip, pckt_ip):
        """ Check is IP is in the rule """

        # the rule captures any IP packet
        if rule_ip == "*":
            return True

        # convert rule ip to binary
        rule_ip = self.ip_to_binary(rule_ip)
        rule_ip = rule_ip[0]
        rule_range = rule_ip[1]

        # convert packet ip to binary
        pckt_ip = self.ip_to_binary(pckt_ip)
        pckt_ip = pckt_ip[0]
        pckt_ip = pckt_ip[1]

        return


    def run(self):
        """ run the program """
        # parse the arguments
        filename = self.parse_args()

        # parse the firewall rules
        self.parse_file(filename)

        # parse stdin
        for line in sys.stdin:
            # parse the line
            packet = self.parse_packet(line)

            result = self.check_rule(packet)
    
        return


if __name__ == "__main__":
    fw = Firewall()
    fw.run()