import tkinter as tk
import os
import sys
import subprocess
import json

import blue as blue
import jsonschema
from jsonschema import validate
from jsonschema import Draft202012Validator
import rule_engine
from cvss import CVSS3


# --- functions ---

def cvss_calc(vector):
    print()
    print("Vulnerability Level:")
    print()
    c = CVSS3(vector)
    print(c.clean_vector())
    print("Base vulnerability score: ", c.base_score)
    sev = c.severities()
    print("Vulnerability Level: ", sev[0])


def source_schema():
    """ _summary_
    A function to load the schema.
    """
    with open('tool_schema_unnested.json', 'r', encoding='utf-8') as schema:
        schema = json.load(schema)
    return schema


def validate_json(json_data):
    """_summary_
    A function to validate json input against JSON schema

    Args:
        json_data (json): inputted JSON data
    """
    json_schema = source_schema()

    try:
        validate(instance=json_data, schema=json_schema, cls=Draft202012Validator)
    except jsonschema.exceptions.ValidationError as err:
        print(err)
        err = "JSON data invalid, please follow guide."
        return False, err

    valid_message = "JSON data validated"
    return True, valid_message


sensor_list = []  # contains list of sensors appended from dict below

# opens input and loops through the dict objects before appending to list
with open('input.txt', 'r', encoding='utf-8') as inp:
    for jsonObj in inp:
        sensor_dict = json.loads(jsonObj)
        sensor_list.append(sensor_dict)

# informs if JSON parsed is valid and will print issues if not
isValid, msg = validate_json(sensor_dict)
print(msg)


def node_capturing_rules():
    node_rule_1 = rule_engine.Rule(
        'data_storage == true'
    )

    filter_node_rule_1 = tuple(node_rule_1.filter(sensor_list))

    if filter_node_rule_1:
        print("-" * 80)
        print("Sensor vulnerability found: Data stored on device")
        print()
        print("Threat: Node capturing - if node captured data might be obtained by an adversary")
        print()
        print("Control: Please make sure data on device is encrypted if possible")
        print()
        for sensor in filter_node_rule_1:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to {0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

        print("-" * 80)


def anti_tamper_rules():
    at_rule_1 = rule_engine.Rule(
        'anti_tamper_destruction == false'
    )

    filter_at_rule_1 = tuple(at_rule_1.filter(sensor_list))

    if filter_at_rule_1:
        print("-" * 80)
        print("Sensor vulnerability found: Sensor not tamper proof")
        print()
        print("Threat: Node capturing - if node captured data might be obtained by an adversary")
        print("Threat: Denial of Service Attack - Should the sensor be a cluster head, "
              "this may cause data to not reach the sink. \nData from important sensors"
              " may also be lost.")
        print()
        print("Control: Install a sensor with a secure element that has a tamper resistance mechanism")
        print()
        for sensor in filter_at_rule_1:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

    print("-" * 80)


def battery_information_rule():
    battery_rule_1 = rule_engine.Rule(
        'accessible_battery_data == false'
    )

    filter_battery_rule_1 = tuple(battery_rule_1.filter(sensor_list))

    if filter_battery_rule_1:
        print("-" * 80)
        print("Sensor vulnerability found: Battery information not shared")
        print()
        print("Threat: Other threats such as Collision, Unfairness and De-synchronisation "
              "may not be flagged before sensor battery depleted.")
        print("Threat: Denial of Service Attack - if the sensors battery is"
              "depleted through other attack vectors, the sensor will no longer be"
              "able to transmit data.")
        print()
        print("Control: Enable battery data transmission if available.")
        print()
        for sensor in filter_battery_rule_1:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

        print("-" * 80)


def communication_rules():
    comm_rule_1 = rule_engine.Rule(
        'connection_type == ["MiWi"]'
    )
    filter_comm_rule_1 = tuple(comm_rule_1.filter(sensor_list))

    comm_rule_2 = rule_engine.Rule(
        'connection_type == ["Zigbee"]'
    )

    filter_comm_rule_2 = tuple(comm_rule_2.filter(sensor_list))

    if filter_comm_rule_1:
        print("-" * 80)
        print("Sensor vulnerability found: Sensor using communication protocol 'MiWi'."
              " 'MiWi' has an issue with version 6.5 and lower. In 6.5,"
              " full frame counters are validated before message authentication.")
        print()
        print("Threat: Denial of Service Attack - Valid packets will not be able to pass through"
              " the network.")
        print("Threat: Replay attack in the stack.")
        print()
        print("Control: Update all sensors using MiWi to current patched version.")
        print()
        for sensor in filter_comm_rule_1:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

        print("-" * 80)

    if filter_comm_rule_2:
        print("-" * 80)
        print("Sensor vulnerability found: Sensor using Zigbee as communication "
              "protocol. ZigBee standard provides a default value for link key to ensure interoperability between "
              "ZigBee devices from different manufacturers")
        print()
        print("Threat: Attackers can use the default key to join the network using their own rogue sensor.")
        print("Consequential threats:")
        print("Threat: Node impersonation. Attackers may wish to impersonate other nodes to direct traffic to them "
              "implying that they are a trustworthy node. \nThis can result in routing information modification, "
              "false sensor readings, causing network congestion, gaining secret keys and other attack vectors.")
        print("Threat: Eavesdropping. Attackers will be able to detect the contents of communications to their rogue "
              "node as well as it's connected neighbours. \nThis could lead to other attacks such as wormholes. They "
              "may also delete the privacy protection in place, thus reducing the data confidentiality of the "
              "network.")
        print()
        print("Control: Please make sure that any default keys used by the protocol have been changed.")
        for sensor in filter_comm_rule_2:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

        print("-" * 80)

    if filter_comm_rule_2:
        print("-" * 80)
        print("Sensor vulnerability found: Sensor using Zigbee as communication protocol. Zigbee is susceptible to "
              "link layer jamming.")
        print()
        print("Threat: This is a MAC layer exploited through transmitting bursts of random ZigBee frames containing "
              "meaningless data on the network at random intervals or specific intervals. \nIt generally targets "
              "specific nodes, leading to packet drop and a DoS attack in the network.")
        print()
        print("Controls:")
        print("Limit the rate of MAC requests.")
        print("Use small frames.")
        print("Identity protection - Radio Resource Test")
        for sensor in filter_comm_rule_2:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

        print("-" * 80)

    if filter_comm_rule_2:
        print("-" * 80)
        print("Sensor vulnerability found: Sensor using ZigBee as communication protocol. Zigbee is vulnerable to ACK "
              "spoofing attacks as is does not \nprovide frame integrity and confidentiality protections for "
              "acknowledgment packets. Link layer jamming is required for this attack.")
        print()
        print("Threat: Attackers jam the network so that a legitimate device does not receive frames."
              "\nThe attacker then sends an ACK frame with a correct sequence number to the original sender. \nThis "
              "attack will lead to data loss in the network.")
        print()
        print("Control: Configuring the network to use other routes when detecting misbehaviour of a node. \nUse strong"
              " authentication and link layer encryption.")
        for sensor in filter_comm_rule_1:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

        print("-" * 80)


def boot_rule():
    boot_rule_1 = rule_engine.Rule(
        'secure_boot == false'
    )

    filter_boot_rule_1 = tuple(boot_rule_1.filter(sensor_list))

    if filter_boot_rule_1:
        print("-" * 80)
        print("Sensor vulnerability found: Sensor does not securely boot")
        print()
        print("Threat: Tampering - the device is vulnerable to physical tampering")
        print("Threat: Node outage - threat actor can upload malicious packages to the"
              " sensor and cause it to stop working.")
        print("Threat: Node impersonation - Threat actors will find it much easier to"
              " capture the node in the boot phase if it is not secure")
        print()
        print("Control: Enable secure boot")
        print()
        for sensor in filter_boot_rule_1:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])


def update_rules():
    update_rule_1 = rule_engine.Rule(
        'update_process == "none"'
    )

    filter_update_rule_1 = tuple(update_rule_1.filter(sensor_list))

    update_rule_2 = rule_engine.Rule(
        'reset_functionality == false'
    )

    filter_update_rule_2 = tuple(update_rule_2.filter(sensor_list))

    if filter_update_rule_1:
        print("-" * 80)
        print("Sensor vulnerability found: Sensor does not have an update function")
        print()
        print("Threat: Should the node have a vulnerability, there is no way to update it. "
              "This will mean that the node will remain vulnerable until removed from the network")
        print()
        print("Control: Make sure all nodes are updatable (physically or remotely) and "
              "maintain current patches on all nodes where possible.")
        print()
        for sensor in filter_update_rule_1:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to {0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

        print("-" * 80)

    if filter_update_rule_2:
        print("-" * 80)
        print("Sensor vulnerability found: Sensor does not have a reset")
        print()
        print("Threat: Should the node have a vulnerability, there is no way to update it. "
              "This will mean that the node will remain vulnerable until removed from the network")
        print()
        print("Control: Make sure all nodes are resettable (physically or remotely).")
        print()
        for sensor in filter_update_rule_2:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

        cvss_calc('CVSS:3.0/S:U/C:H/I:H/A:L/AV:L/AC:L/PR:L/UI:R')

        print("-" * 80)


def routing_protocol_rules():
    routing_rule_1 = rule_engine.Rule(
        'network_routing_protocols == ["LEACH"]'
    )

    filter_routing_rule_1 = tuple(routing_rule_1.filter(sensor_list))

    if filter_routing_rule_1:
        print("-" * 80)
        print("Sensor vulnerability found: Sensor using LEACH as a network"
              " routing protocol")
        print()
        print("Threat: LEACH protocol is vulnerable to HELLO flood attacks due to it's "
              "clustering algorithm. \n\t\tThis is due to it operating a cluster head "
              "system based on Received Signal Strength (RSS).")
        print()
        print("Control: If LEACH is required, please look at using R-LEACH which "
              "addresses these security requirements.")
        print()
        for sensor in filter_routing_rule_1:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])


def cve_2020_10757():
    node_rule_1 = rule_engine.Rule(
        'data_storage == true'
    )

    filter_node_rule_1 = tuple(node_rule_1.filter(sensor_list))

    ubuntu_rule_1 = rule_engine.Rule(
        'operating_system == "Ubuntu"'
    )

    filter_ubuntu_rule_1 = tuple(ubuntu_rule_1.filter(sensor_list))

    ubuntu_version_rule_1 = rule_engine.Rule(
        'software_version == "16.04"'
    )

    filter_ubuntu_version_rule_1 = tuple(ubuntu_version_rule_1.filter(sensor_list))

    ubuntu_version_rule_2 = rule_engine.Rule(
        'software_version == "18.04"'
    )

    filter_ubuntu_version_rule_2 = tuple(ubuntu_version_rule_2.filter(sensor_list))

    ubuntu_version_rule_3 = rule_engine.Rule(
        'software_version == "20.04"'
    )

    filter_ubuntu_version_rule_3 = tuple(ubuntu_version_rule_3.filter(sensor_list))

    debian_rule_1 = rule_engine.Rule(
        'operating_system == "Debian"'
    )

    filter_debian_rule_1 = tuple(debian_rule_1.filter(sensor_list))

    debian_version_rule_1 = rule_engine.Rule(
        'software_version == "8.0"'
    )

    filter_debian_version_rule_1 = tuple(debian_version_rule_1.filter(sensor_list))

    if filter_node_rule_1:
        if filter_ubuntu_rule_1:
            if filter_ubuntu_version_rule_1:
                print("Sensor vulnerability found: A flaw was found in the Linux Kernel in versions after "
                      "4.5-rc1 in the way mremap handled DAX Huge Pages. \n\t\t\t\t\t\t\tThis flaw allows a local "
                      "attacker with access to a DAX enabled storage to escalate their privileges on the system. "
                      "\n\t\t\t\t\t\t\tThis vulnerability affects Ubuntu Linux Version 16.04.")
                print()
                print("Threat: There is total information disclosure, resulting in all system files being revealed.")
                print("Threat: There is a total compromise of system integrity. There is a complete loss of system "
                      "protection, resulting in the entire system being compromised.")
                print("Threat: There is a total shutdown of the affected sensor. The attacker can render the "
                      "resource completely unavailable.")
                print()
                print("Control: Please download the required bug fix. More information "
                      "can be found here: https://www.cvedetails.com/cve/CVE-2020-10757/")
                for sensor in filter_ubuntu_version_rule_1:
                    print("Affected Sensor:")
                    print(sensor['sensor_id'])
                    print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
                    print(sensor['connected_sensors'])

            print("-" * 80)

    if filter_node_rule_1:
        if filter_ubuntu_rule_1:
            if filter_ubuntu_version_rule_2:
                print("Sensor vulnerability found: A flaw was found in the Linux Kernel in versions after "
                      "4.5-rc1 in the way mremap handled DAX Huge Pages. \n\t\t\t\t\t\t\tThis flaw allows a local "
                      "attacker with access to a DAX enabled storage to escalate their privileges on the system. "
                      "\n\t\t\t\t\t\t\tThis vulnerability affects Ubuntu Linux Version 18.04.")
                print()
                print("Threat: There is total information disclosure, resulting in all system files being revealed.")
                print("Threat: There is a total compromise of system integrity. There is a complete loss of system "
                      "protection, resulting in the entire system being compromised.")
                print("Threat: There is a total shutdown of the affected sensor. The attacker can render the "
                      "resource completely unavailable.")
                print()
                print("Control: Please download the required bug fix. More information "
                      "can be found here: https://www.cvedetails.com/cve/CVE-2020-10757/")
                for sensor in filter_ubuntu_version_rule_2:
                    print("Affected Sensor:")
                    print(sensor['sensor_id'])
                    print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
                    print(sensor['connected_sensors'])

            print("-" * 80)

    if filter_node_rule_1:
        if filter_ubuntu_rule_1:
            if filter_ubuntu_version_rule_3:
                print("Sensor vulnerability found: A flaw was found in the Linux Kernel in versions after "
                      "4.5-rc1 in the way mremap handled DAX Huge Pages. \n\t\t\t\t\t\t\tThis flaw allows a local "
                      "attacker with access to a DAX enabled storage to escalate their privileges on the system. "
                      "\n\t\t\t\t\t\t\tThis vulnerability affects Ubuntu Linux Version 20.04.")
                print()
                print("Threat: There is total information disclosure, resulting in all system files being revealed.")
                print("Threat: There is a total compromise of system integrity. There is a complete loss of system "
                      "protection, resulting in the entire system being compromised.")
                print("Threat: There is a total shutdown of the affected sensor. The attacker can render the "
                      "resource completely unavailable.")
                print()
                print("Control: Please download the required bug fix. More information "
                      "can be found here: https://www.cvedetails.com/cve/CVE-2020-10757/")
                for sensor in filter_ubuntu_version_rule_3:
                    print("Affected Sensor:")
                    print(sensor['sensor_id'])
                    print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
                    print(sensor['connected_sensors'])

    if filter_node_rule_1:
        if debian_rule_1:
            if filter_debian_rule_1:
                print("-" * 80)
                print("Sensor vulnerability found: A flaw was found in the Linux Kernel in versions after "
                      "4.5-rc1 in the way mremap handled DAX Huge Pages. \n\t\t\t\t\t\t\tThis flaw allows a local "
                      "attacker with access to a DAX enabled storage to escalate their privileges on the system. "
                      "\n\t\t\t\t\t\t\tThis vulnerability affects Debian Linux Version 8.0.")
                print()
                print("Threat: There is total information disclosure, resulting in all system files being revealed.")
                print("Threat: There is a total compromise of system integrity. There is a complete loss of system "
                      "protection, resulting in the entire system being compromised.")
                print("Threat: There is a total shutdown of the affected sensor. The attacker can render the "
                      "resource completely unavailable.")
                print()
                print("Control: Please download the required bug fix. More information "
                      "can be found here: https://www.cvedetails.com/cve/CVE-2020-10757/")
                for sensor in filter_debian_version_rule_1:
                    print("Affected Sensor:")
                    print(sensor['sensor_id'])
                    print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
                    print(sensor['connected_sensors'])

            print("-" * 80)


def log4j():
    log4j_rule = rule_engine.Rule(
        'dependencies == ["log4j"]'
    )

    filter_log4j_rule = tuple(log4j_rule.filter(sensor_list))

    if filter_log4j_rule:
        print("-" * 80)
        print("Sensor vulnerability found: Log4j dependency used. A flaw was found in the Apache Log4j logging "
              "library in versions from 2.0.0 and before 2.15.0. \n\t\t\t\t\t\t\tA remote attacker who can control log "
              "messages or log message parameters, can execute arbitrary code on the server via JNDI LDAP endpoint.")
        print()
        print("Threat: Attackers can read all sensitive data collected in logs")
        print()
        print("Control: Update log4j to a version beyond 2.15.0 (preferably "
              "current version. Alternative use another logging option.")
        for sensor in filter_log4j_rule:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

        cvss_calc('CVSS:3.0/S:C/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N')


def authentication_rules():
    authentication_rule_1 = rule_engine.Rule(
        'authentication == "LEAP"'
    )

    filter_authentication_rule_1 = tuple(authentication_rule_1.filter(sensor_list))

    if filter_authentication_rule_1:
        print("-" * 80)
        print("Sensor vulnerability found: Sensor using LEAP for authentication. LEAP is vulnerable to dictionary "
              "attacks.")
        print("Threat: Attacker can guess default and easily guessable passwords and authenticate themselves on the "
              "network.")
        print()
        print("Control: Please use strong passwords.")
        for sensor in filter_authentication_rule_1:
            print("Affected Sensor:")
            print(sensor['sensor_id'])
            print("Connected sensors to sensor{0} that may be at risk:".format(sensor['sensor_id']))
            print(sensor['connected_sensors'])

        print("-" * 80)


# --- classes ---

class Redirect:

    def __init__(self, widget):
        self.widget = widget
        self.geometry = None

    def write(self, text):
        self.widget.insert('end', text)
        # self.widget.see('end') # autoscroll


# --- main ---

root = tk.Tk()
root.title("Analyse")

text = tk.Text(root)
text.pack()


analyse = tk.Button(root, text='Analyse', command=lambda: [node_capturing_rules(), node_capturing_rules(),
                                                           anti_tamper_rules(),
                                                           battery_information_rule(),
                                                           boot_rule(),
                                                           update_rules(),
                                                           routing_protocol_rules(),
                                                           cve_2020_10757(),
                                                           log4j(),
                                                           communication_rules()])

analyse.pack()

old_stdout = sys.stdout
sys.stdout = Redirect(text)

root.mainloop()

sys.stdout = old_stdout
