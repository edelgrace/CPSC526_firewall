# Edel Altares 10098725 Tutorial 2

import os
import sys
import time
import math
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

        if rule[0] == "#":
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


    def rule_to_dict(self, rule, count):
        """ Convert rule to dictionary """

        direction = str(rule[0])
        action = str(rule[1])
        ip = str(rule[2])
        ports = str(rule[3]).split(",")
        
        if rule[-1] == rule[3]:
            established = 0
        else:
            established = 1

        # create a dict out of the the rule
        dict = {'action': action,
                'ip': ip,
                'direction': direction,
                'port': ports,
                'established': established,
                'line': count
            }

        return dict


    def parse_file(self, filename):
        """ Parse the file """

        # go through each line in the file
        with open(filename, 'r') as file:
            count = 0

            for line in file:

                count += 1

                # split line with whitespace
                rule_data = line.strip().split()

                # rule is valid
                if  self.valid_rule(rule_data):

                    # add to rule list
                    rule = self.rule_to_dict(rule_data, count)
                    self.RULES.append(rule)

                # rule is not valid
                else:
                    sys.stderr.write(str(count) + " Warning: An invalid rule was encountered\n")

        return


    def parse_packet(self, packet):
        """ parse packet """

        # split packet
        packet = packet.strip().split()
        
        if len(packet) != 4:
            return False
            
        if packet[0] == "#":
            return False

        # make a dictionary from the packet line
        try:
            direction = str(packet[0])
            ip = str(packet[1])
            port = int(packet[2])
            flag = int(packet[3])

            dict = {
                'direction': direction,
                'ip': ip,
                'port': port,
                'established': flag    
            }
        # print error
        except Exception as e:
            sys.stderr.write("Warning: Invalid packet " + str(e))

        return dict


    def check_rule(self, packet):
        """ check packet against rule """

        flag = True
        no_match = True

        # go through each rule
        for rule in self.RULES:
            # check if same direction
            if rule['direction'] != packet['direction']:
                flag = False

            # check if ip is in the rule
            if not self.check_ip(rule['ip'], packet['ip']):
                flag = False

            # check if port is same
            if not self.check_port(rule['port'], packet['port']):
                flag = False

            # check if established
            if rule['established'] != packet['established'] and rule['established'] != 0:
                flag = False

            # print result
            if flag:

                msg = rule['action'] + "(" + str(rule['line']) + ") " + packet['direction'] 
                msg += " " + packet['ip'] + " " + str(packet['port']) + " " + str(packet['established'])
                msg += "\n"

                sys.stdout.write(msg)
            
                no_match = False

                break

            # reset the flag
            else:
                flag = True

        # print dropped
        if no_match:
            msg = "drop() " + packet['direction'] + " " + packet['ip'] + " "
            msg += str(packet['port']) + " " + str(packet['established'])
            msg += "\n"

            sys.stdout.write(msg)

        return


    def mask_to_octet(self, mask):
        """ Convert mask to binary """

        mask_binary = []
        mask = int(mask)
        count = mask

        # compute each octet
        while count > 0:
            if count -8 >= 0:
                mask_binary.append(255)
                count -= 8

            # calculate number with remaining count
            else:
                octet = 0

                while count-1 >= 0:
                    octet += math.pow(2,8-count)

                    count -=1

                mask_binary.append(int(octet))

        # add 0s
        while len(mask_binary) < 4:
            mask_binary.append(0)

        return mask_binary


    def check_ip(self, rule_ip, pckt_ip):
        """ Check is IP is in the rule """

        # the rule captures any IP packet
        if rule_ip == "*":
            return True

        # convert rule ip to lists
        rule_ip = self.ip_range(rule_ip)
        rule_mask = rule_ip[1]
        rule_ip = rule_ip[0]

        # convert packet ip to lists
        pckt_ip = self.ip_range(pckt_ip)
        pckt_ip = pckt_ip[0]

        pckt = []

        for x in range(0,len(rule_ip)):

            # AND the mask and packet ip address
            pckt.append(pckt_ip[x] & rule_mask[x])
            rule_ip[x] = rule_ip[x] & rule_mask[x]

        # check if network portions are equal
        return pckt == rule_ip


    def check_port(self, rule_port, pckt_port):
        """ Check ports """

        # check if any ports used
        if rule_port == ["*"]:
            return True

        ports = []

        # convert ports to ints
        for port in rule_port:
            ports.append(int(port.strip()))

        return pckt_port in ports


    def ip_range(self, ip):
        """ Convert an ip address to octets """

        ip_addr = []

        # split into octets
        ip = ip.split(".")
        range = ip[3].split("/")
        ip[3] = range[0]

        for octet in ip:
            ip_addr.append(int(octet))

        # convert range to octet
        if range[0] != range[-1]:
            mask = self.mask_to_octet(range[1])
        else:
            mask = [255,255,255,255]

        # return the binary
        return [ip_addr, mask]


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
            
            # check if packet was valid
            if not packet:
                sys.stderr.write("Warning: Invalid packet encountered")
        
            else:
                result = self.check_rule(packet)
    
        return


if __name__ == "__main__":
    try:
        fw = Firewall()
        fw.run()
    except Exception as e:
        sys.stderr.write("ERROR: " + str(e))
