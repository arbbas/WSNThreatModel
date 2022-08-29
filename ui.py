from tkinter import *
from tkinter.ttk import *
from tkinter.filedialog import askopenfile
import time
import sys
import tkinter as tk
import json
import jsonschema
from jsonschema import validate
from jsonschema import Draft202012Validator
import rule_engine
from cvss import CVSS3
import pyfiglet

# --------------- threat calculations --------------------

# int variables to store the amount of threats in each threat category
critical_threats = 0
high_threats = 0
medium_threats = 0
low_threats = 0


def threat_counter():
    print("Threat count summary:")
    print("\tCritical threat count: {0}".format(critical_threats))
    print("\tHigh threat count: {0}".format(high_threats))
    print("\tMedium threat count: {0}".format(medium_threats))
    print("\tLow threat count: {0}".format(low_threats))
    print()
    print("Thank you for using WSN Threat Modelling Tool. Please address the {0} critical threat(s) and {1} high"
          " threat(s) as soon as \npossible".format(critical_threats, high_threats))
    print()
    print("Please scroll up to read the full report.")


def cvss_calc(vector):
    print("*" * 20)
    print("Vulnerability Level:")
    print()
    c = CVSS3(vector)
    print(c.clean_vector())
    print("Base vulnerability score: ", c.base_score)
    sev = c.severities()
    print("Vulnerability Level: ", sev[0])


# --------------- JSON related --------------------


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


# --------------- rules --------------------

def introduction():
    print("Threat report generated. Please scroll to the bottom of the report for total threats "
          "in each CVSS category.")


def node_capturing_rules():
    node_rule_1 = rule_engine.Rule(
        'data_storage == true'
    )

    filter_node_rule_1 = tuple(node_rule_1.filter(sensor_list))

    if filter_node_rule_1:
        global high_threats
        print("-" * 123)
        print('Sensor vulnerability found: ',
              "Data stored on device")
        print("*" * 20)
        print("Threat: ",
              "Node capturing - if node captured data might be obtained by an adversary.")
        print("*" * 20)
        print("Control(s): ", "Please make sure data on device is encrypted if possible.")
        print("*" * 20)
        for sensor in filter_node_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:H/I:H/A:L/AV:P/AC:L/PR:N/UI:R')
        high_threats += 1

        print("-" * 123)


def anti_tamper_rules():
    at_rule_1 = rule_engine.Rule(
        'anti_tamper_destruction == false'
    )

    filter_at_rule_1 = tuple(at_rule_1.filter(sensor_list))

    if filter_at_rule_1:
        global medium_threats
        print("-" * 123)
        print("Sensor vulnerability found: Sensor not tamper proof")
        print("*" * 20)
        print("Threat: Node capturing - if node captured data might be obtained by an adversary.")
        print("*" * 20)
        print("Threat: Denial of Service Attack - Should the sensor be a cluster head, "
              "this may cause data to not reach the sink. Data from \nimportant sensors"
              " may also be lost.\n")
        print("*" * 20)
        print("Control(s): Install a sensor with a secure element that has a tamper resistance mechanism.")
        print("*" * 20)
        for sensor in filter_at_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:U/C:H/I:L/A:H/AV:P/AC:L/PR:N/UI:R')
        medium_threats += 1
        print("-" * 123)


def battery_information_rule():
    battery_rule_1 = rule_engine.Rule(
        'accessible_battery_data == false'
    )

    filter_battery_rule_1 = tuple(battery_rule_1.filter(sensor_list))

    if filter_battery_rule_1:
        global high_threats
        print("-" * 123)
        print("Sensor vulnerability found: Battery information not shared")
        print("*" * 20)
        print("Threat: Other threats such as Collision, Unfairness and De-synchronisation "
              "may not be flagged before sensor battery \ndepleted.")
        print("*" * 20)
        print("Threat: Denial of Service Attack - if the sensors battery is"
              "depleted through other attack vectors, the sensor will no \nlonger be "
              "able to transmit data.")
        print("*" * 20)
        print("Control(s): Enable battery data transmission if available.")
        print("*" * 20)
        for sensor in filter_battery_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:U/C:L/I:L/A:H/AV:N/AC:L/PR:N/UI:N')
        high_threats += 1
        print("-" * 123)


def communication_rules():
    comm_rule_1 = rule_engine.Rule(
        'connection_type == ["MiWi"]'
    )
    filter_comm_rule_1 = tuple(comm_rule_1.filter(sensor_list))

    comm_rule_2 = rule_engine.Rule(
        'connection_type == ["Zigbee"]'
    )

    filter_comm_rule_2 = tuple(comm_rule_2.filter(sensor_list))

    global medium_threats
    global high_threats

    if filter_comm_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor using communication protocol 'MiWi'."
              " 'MiWi' has an issue with version 6.5 and lower. In 6.5,"
              " full frame counters are validated before message authentication.")
        print("*" * 20)
        print("Threat: Denial of Service Attack - Valid packets will not be able to pass through"
              " the network.")
        print("*" * 20)
        print("Threat: Replay attack in the stack.")
        print("*" * 20)
        print("Control(s): Update all sensors using MiWi to current patched version.")
        print("*" * 20)
        for sensor in filter_comm_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:U/C:L/I:H/A:H/AV:N/AC:H/PR:L/UI:R')
        medium_threats += 1
        print("-" * 123)

    if filter_comm_rule_2:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor using Zigbee as communication "
              "protocol. ZigBee standard provides a default value \nfor link key to ensure interoperability between "
              "ZigBee devices from different manufacturers")
        print("*" * 20)
        print("Threat: Attackers can use the default key to join the network using their own rogue sensor.")
        print("*" * 20)
        print("Threat: Node impersonation. Attackers may wish to impersonate other nodes to direct traffic to them "
              "implying that \nthey are a trustworthy node. This can result in routing information modification, "
              "false sensor readings, \ncausing network congestion, gaining secret keys and other attack vectors.")
        print("*" * 20)
        print("Threat: Eavesdropping. Attackers will be able to detect the contents of communications to their rogue "
              "node as well as \nit's connected neighbours. This could lead to other attacks such as wormholes. They "
              "may also delete the privacy \nprotection in place, thus reducing the data confidentiality of the "
              "network.")
        print("*" * 20)
        print("Control(s): Please make sure that any default keys used by the protocol have been changed.")
        print("*" * 20)
        for sensor in filter_comm_rule_2:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:H/I:H/A:L/AV:N/AC:H/PR:H/UI:R')
        high_threats += 1
        print("-" * 123)

    if filter_comm_rule_2:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor using Zigbee as communication protocol. Zigbee is susceptible to "
              "link layer \njamming.")
        print("*" * 20)
        print("Threat: This is a MAC layer exploited through transmitting bursts of random ZigBee frames containing "
              "meaningless \ndata on the network at random intervals or specific intervals. It generally targets "
              "specific nodes, leading \nto packet drop and a DoS attack in the network.")
        print("*" * 20)
        print("Control(s):")
        print("1) Limit the rate of MAC requests.")
        print("2) Use small frames.")
        print("3) Identity protection - Radio Resource Test")
        print("*" * 20)
        for sensor in filter_comm_rule_2:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:L/I:H/A:H/AV:N/AC:H/PR:L/UI:R')
        high_threats += 1
        print("-" * 123)

    if filter_comm_rule_2:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor using ZigBee as communication protocol. Zigbee is vulnerable to ACK "
              "spoofing \nattacks as is does not provide frame integrity and confidentiality protections for "
              "acknowledgment packets. Link \nlayer jamming is required for this attack.")
        print("*" * 20)
        print("Threat: Attackers jam the network so that a legitimate device does not receive frames."
              " The attacker then sends \nan ACK frame with a correct sequence number to the original sender. This "
              "attack will lead to data loss in \nthe network.")
        print("*" * 20)
        print("Control(s):\n1) Configuring the network to use other routes when detecting misbehaviour of a node. "
              "\n2) Use strong authentication and link layer encryption.")
        print("*" * 20)
        for sensor in filter_comm_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:L/I:H/A:H/AV:N/AC:H/PR:L/UI:R')
        high_threats += 1
        print("-" * 123)


def boot_rule():
    boot_rule_1 = rule_engine.Rule(
        'secure_boot == false'
    )

    filter_boot_rule_1 = tuple(boot_rule_1.filter(sensor_list))

    global high_threats

    if filter_boot_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor does not securely boot")
        print("*" * 20)
        print("Threat: Tampering - the device is vulnerable to physical tampering.")
        print("*" * 20)
        print("Threat: Node outage - threat actor can upload malicious packages to the"
              " sensor and cause it to stop working.")
        print("*" * 20)
        print("Threat: Node impersonation - Threat actors will find it much easier to"
              " capture the node in the boot phase if it is not \nsecure.")
        print("*" * 20)
        print("Control(s): Enable secure boot")
        print("*" * 20)
        for sensor in filter_boot_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:U/C:H/I:L/A:H/AV:L/AC:L/PR:N/UI:R')
        high_threats += 1
        print("-" * 123)


def update_rules():
    update_rule_1 = rule_engine.Rule(
        'update_process == "none"'
    )

    filter_update_rule_1 = tuple(update_rule_1.filter(sensor_list))

    update_rule_2 = rule_engine.Rule(
        'reset_functionality == false'
    )

    filter_update_rule_2 = tuple(update_rule_2.filter(sensor_list))

    global medium_threats

    if filter_update_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor does not have a remote update function")
        print("*" * 20)
        print("Threat: Should the node have a vulnerability, there is no way to update it remotely. "
              "This will mean that the node will \nremain vulnerable until physically removed from the network."
              " for a manual update.")
        print("*" * 20)
        print("Control(s): Make sure all nodes are updatable (physically or remotely) and "
              "maintain current patches on all nodes where \npossible.")
        print("*" * 20)
        for sensor in filter_update_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:U/C:N/I:N/A:H/AV:L/AC:L/PR:L/UI:R')
        medium_threats += 1
        print("-" * 123)

    if filter_update_rule_2:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor does not have a reset")
        print("*" * 20)
        print("Threat: Should the node have a vulnerability, there is no way to update it. "
              "This will mean that the node will remain \nvulnerable until removed from the network")
        print("*" * 20)
        print("Control: Make sure all nodes are resettable (physically or remotely).")
        print("*" * 20)
        for sensor in filter_update_rule_2:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:U/C:H/I:H/A:L/AV:L/AC:L/PR:L/UI:R')
        medium_threats += 1
        print("-" * 123)


def routing_protocol_rules():
    routing_rule_1 = rule_engine.Rule(
        'network_routing_protocols == ["LEACH"]'
    )

    filter_routing_rule_1 = tuple(routing_rule_1.filter(sensor_list))

    global high_threats

    if filter_routing_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor using LEACH as a network"
              " routing protocol")
        print("*" * 20)
        print("Threat: LEACH protocol is vulnerable to HELLO flood attacks due to it's "
              "clustering algorithm. This is due to it \noperating a cluster head "
              "system based on Received Signal Strength (RSS).")
        print("*" * 20)
        print("Control: If LEACH is required, please look at using R-LEACH which "
              "addresses these security requirements.")
        print("*" * 20)
        for sensor in filter_routing_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:L/I:L/A:H/AV:N/AC:H/PR:L/UI:R')
        high_threats += 1
        print("-" * 123)


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

    global high_threats

    if filter_node_rule_1:
        if filter_ubuntu_rule_1:
            if filter_ubuntu_version_rule_1:
                print("-" * 123)
                print("Sensor vulnerability found: A flaw was found in the Linux Kernel in versions after "
                      "4.5-rc1 in the way mremap handled \nDAX Huge Pages. This flaw allows a local "
                      "attacker with access to a DAX enabled storage to escalate \ntheir privileges on the system. "
                      "This vulnerability affects Ubuntu Linux Version 16.04.")
                print("*" * 20)
                print("Threat: There is total information disclosure, resulting in all system files being revealed.")
                print("*" * 20)
                print("Threat: There is a total compromise of system integrity. There is a complete loss of system "
                      "protection, resulting in the entire system being compromised.")
                print("*" * 20)
                print("Threat: There is a total shutdown of the affected sensor. The attacker can render the "
                      "resource completely unavailable.")
                print("*" * 20)
                print("Control: Please download the required bug fix. More information "
                      "can be found here: \nhttps://www.cvedetails.com/cve/CVE-2020-10757/")
                print("*" * 20)
                for sensor in filter_ubuntu_version_rule_1:
                    print("Affected Sensor: ", *sensor['sensor_id'])
                    print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                    print(*sensor['connected_sensors'], sep=', ')
                    print()

                cvss_calc('CVSS:3.0/S:U/C:H/I:H/A:H/AV:L/AC:L/PR:L/UI:R')
                high_threats += 1
                print("-" * 123)

    if filter_node_rule_1:
        if filter_ubuntu_rule_1:
            if filter_ubuntu_version_rule_2:
                print("-" * 123)
                print("Sensor vulnerability found: A flaw was found in the Linux Kernel in versions after "
                      "4.5-rc1 in the way mremap handled \nDAX Huge Pages. This flaw allows a local "
                      "attacker with access to a DAX enabled storage to escalate \ntheir privileges on the system. "
                      "This vulnerability affects Ubuntu Linux Version 18.04.")
                print("*" * 20)
                print("Threat: There is total information disclosure, resulting in all system files being revealed.")
                print("*" * 20)
                print("Threat: There is a total compromise of system integrity. There is a complete loss of system "
                      "protection, resulting in the entire system being compromised.")
                print("*" * 20)
                print("Threat: There is a total shutdown of the affected sensor. The attacker can render the "
                      "resource completely unavailable.")
                print("*" * 20)
                print("Control: Please download the required bug fix. More information "
                      "can be found here: \nhttps://www.cvedetails.com/cve/CVE-2020-10757/")
                print("*" * 20)
                for sensor in filter_ubuntu_version_rule_2:
                    print("Affected Sensor: ", *sensor['sensor_id'])
                    print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                    print(*sensor['connected_sensors'], sep=', ')
                    print()

                cvss_calc('CVSS:3.0/S:U/C:H/I:H/A:H/AV:L/AC:L/PR:L/UI:R')
                high_threats += 1
                print("-" * 123)

    if filter_node_rule_1:
        if filter_ubuntu_rule_1:
            if filter_ubuntu_version_rule_3:
                print("-" * 123)
                print("Sensor vulnerability found: A flaw was found in the Linux Kernel in versions after "
                      "4.5-rc1 in the way mremap handled \nDAX Huge Pages. This flaw allows a local "
                      "attacker with access to a DAX enabled storage to escalate \ntheir privileges on the system. "
                      "This vulnerability affects Ubuntu Linux Version 20.04.")
                print()
                print("Threat: There is total information disclosure, resulting in all system files being revealed.")
                print("Threat: There is a total compromise of system integrity. There is a complete loss of system "
                      "protection, resulting in the entire system being compromised.")
                print("Threat: There is a total shutdown of the affected sensor. The attacker can render the "
                      "resource completely unavailable.")
                print()
                print("Control: Please download the required bug fix. More information "
                      "can be found here: \nhttps://www.cvedetails.com/cve/CVE-2020-10757/")
                for sensor in filter_ubuntu_version_rule_3:
                    print("Affected Sensor: ", *sensor['sensor_id'])
                    print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                    print(*sensor['connected_sensors'], sep=', ')
                    print()

                cvss_calc('CVSS:3.0/S:U/C:H/I:H/A:H/AV:L/AC:L/PR:L/UI:R')
                high_threats += 1
                print("-" * 123)

    if filter_node_rule_1:
        if debian_rule_1:
            if filter_debian_rule_1:
                print("-" * 123)
                print("Sensor vulnerability found: A flaw was found in the Linux Kernel in versions after "
                      "4.5-rc1 in the way mremap handled \nDAX Huge Pages. This flaw allows a local "
                      "attacker with access to a DAX enabled storage to escalate \ntheir privileges on the system. "
                      "This vulnerability affects Debian Linux Version 8.0.")
                print()
                print("Threat: There is total information disclosure, resulting in all system files being revealed.")
                print("Threat: There is a total compromise of system integrity. There is a complete loss of system "
                      "protection, resulting in the entire system being compromised.")
                print("Threat: There is a total shutdown of the affected sensor. The attacker can render the "
                      "resource completely unavailable.")
                print()
                print("Control: Please download the required bug fix. More information "
                      "can be found here: \nhttps://www.cvedetails.com/cve/CVE-2020-10757/")
                for sensor in filter_debian_version_rule_1:
                    print("Affected Sensor: ", *sensor['sensor_id'])
                    print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                    print(*sensor['connected_sensors'], sep=', ')
                    print()

                cvss_calc('CVSS:3.0/S:U/C:H/I:H/A:H/AV:L/AC:L/PR:L/UI:R')
                high_threats += 1
                print("-" * 123)


def log4j():
    log4j_rule = rule_engine.Rule(
        'dependencies == ["log4j"]'
    )

    filter_log4j_rule = tuple(log4j_rule.filter(sensor_list))

    global critical_threats

    if filter_log4j_rule:
        print("-" * 123)
        print("Sensor vulnerability found: Log4j dependency used. A flaw was found in the Apache Log4j logging "
              "library in versions from 2.0.0 and before 2.15.0. \nA remote attacker who can control log "
              "messages or log message parameters, can execute arbitrary code on the server via JNDI LDAP endpoint.")
        print()
        print("Threat: Attackers can read all sensitive data collected in logs")
        print()
        print("Control: Update log4j to a version beyond 2.15.0 (preferably "
              "current version. Alternative use another logging option.")
        for sensor in filter_log4j_rule:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N')
        print("-" * 123)
        critical_threats += 1


def authentication_rules():
    authentication_rule_1 = rule_engine.Rule(
        'authentication == "LEAP"'
    )

    filter_authentication_rule_1 = tuple(authentication_rule_1.filter(sensor_list))

    if filter_authentication_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor using LEAP for authentication. LEAP is vulnerable to dictionary "
              "attacks.")
        print("Threat: Attacker can guess default and easily guessable passwords and authenticate themselves on the "
              "network.")
        print()
        print("Control: Please use strong passwords.")
        for sensor in filter_authentication_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:H/I:L/A:L/AV:N/AC:H/PR:N/UI:R')

        print("-" * 123)


def shared_resources():
    shared_resources_rule_1 = rule_engine.Rule(
        'shared_resources == true'
    )

    filter_shared_resources_rule_1 = tuple(shared_resources_rule_1.filter(sensor_list))

    global high_threats

    if filter_shared_resources_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor shares resources with connected sensors")
        print("*" * 20)
        print("Threat: Any connected sensors could be at risk if sensor is attacked.")
        print("*" * 20)
        print("Control: Sensors should share resources as little as possible. Please reconfigure where possible.")
        print("*" * 20)
        for sensor in filter_shared_resources_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:H/I:L/A:L/AV:N/AC:H/PR:H/UI:N')
        high_threats += 1
        print("-" * 123)


def lorawan():
    lorawan_rule_1 = rule_engine.Rule(
        'connection_type == ["LoRaWAN"]'
    )
    filter_lorawan_rule_1 = tuple(lorawan_rule_1.filter(sensor_list))

    global high_threats

    if filter_lorawan_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor using LoRaWAN. LoRaWAN is vulnerable to ACK Spoofing.")
        print("*" * 20)
        print("Threat: Information presented could be false.")
        print("*" * 20)
        print("Threat: Could lead to further attacks such as a selective forwarding attack.")
        print("*" * 20)
        print("Threat: Packet loss/corruption")
        print("*" * 20)
        print("Control: ACK messages do not indicate which message they confirm. Authenticated encryption of the MAC "
              "layer \npayload will leave evidence of discarded frames in the frame counter value. The application "
              "server will recognise frame \ncounter disparities as an issue.")
        print("*" * 20)
        for sensor in filter_lorawan_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:L/I:H/A:H/AV:N/AC:H/PR:L/UI:R')
        high_threats += 1
        print("-" * 123)


def encryption():
    encryption_rule_1 = rule_engine.Rule(
        'encryption == ["MD5"]'
    )
    filter_encrytion_rule_1 = tuple(encryption_rule_1.filter(sensor_list))

    global medium_threats

    if filter_encrytion_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Using MD5 hashing algorithm.")
        print("*" * 20)
        print("Threat: MD5 is a deprecated cryptographic algorithm.")
        print("*" * 20)
        print("Threat: Collision attacks can be executed to forge certificates")
        print("*" * 20)
        print("Threat: Any information stored on the sensor hashed with MD5 can be viewed easier than with "
              "none deprecated \nhashing algorithms.")
        print("*" * 20)
        print("Control: Use a more secure hashing algorithm such as SHA-2")
        print("Please see more here: https://vulmon.com/vulnerabilitydetails?qid=CVE-2021-38386&scoretype=cvssv3")
        print("*" * 20)
        for sensor in filter_encrytion_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:U/C:H/I:L/A:L/AV:L/AC:L/PR:N/UI:R')
        medium_threats += 1
        print("-" * 123)


def cve_2021_38386():
    cve_2021_38386_rule_1 = rule_engine.Rule(
        'operating_system == "Contiki"'
    )

    filter_cve_2021_38386_rule_1 = tuple(cve_2021_38386_rule_1.filter(sensor_list))

    cve_2021_38386_rule_2 = rule_engine.Rule(
        'software_version == "3.0"'
    )
    filter_cve_2021_38386_rule_2 = tuple(cve_2021_38386_rule_2.filter(sensor_list))

    global medium_threats

    if filter_cve_2021_38386_rule_1:
        if filter_cve_2021_38386_rule_2:
            print("-" * 123)
            print("Sensor vulnerability found: In Contiki 3.0, a buffer overflow in the Telnet service enables remote "
                  "threat \nactors to launch a denial of service attack because the ls command is mishandled when a"
                  " directory has many \nfiles with long names.")
            print("*" * 20)
            print("Threat: Data availability for the WSN is reduced.")
            print("*" * 20)
            print("Threat: Ongoing issues caused by DoS such as incorrect decisions made within the system.")
            print("*" * 20)
            print("Control: Ensure that any devices operating Telnet services such as edge nodes are hardened and "
                  "have the necessary \nauthentication methods and passwords in place before granting access to remote"
                  " users.")
            print("*" * 20)
            for sensor in filter_cve_2021_38386_rule_2:
                print("Affected Sensor: ", *sensor['sensor_id'])
                print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                print(*sensor['connected_sensors'], sep=', ')
                print()

            cvss_calc('CVSS:3.0/S:U/C:L/I:L/A:L/AV:L/AC:H/PR:L/UI:R')
            medium_threats += 1
            print("-" * 123)


def cve_2014_0323():
    cve_2014_0323_rule_1 = rule_engine.Rule(
        'operating_system == "Windows"'
    )
    filter_cve_2014_0323_rule_1 = tuple(cve_2014_0323_rule_1.filter(sensor_list))

    cve_2014_0323_rule_2 = rule_engine.Rule(
        'software_version == "XP"'
    )
    filter_cve_2014_0323_rule_2 = tuple(cve_2014_0323_rule_2.filter(sensor_list))

    cve_2014_0323_rule_3 = rule_engine.Rule(
        'software_version == "Server 2012"'
    )
    filter_cve_2014_0323_rule_3 = tuple(cve_2014_0323_rule_3.filter(sensor_list))

    cve_2014_0323_rule_4 = rule_engine.Rule(
        'software_version == "Vista"'
    )
    filter_cve_2014_0323_rule_4 = tuple(cve_2014_0323_rule_4.filter(sensor_list))

    cve_2014_0323_rule_5 = rule_engine.Rule(
        'software_version == "7"'
    )
    filter_cve_2014_0323_rule_5 = tuple(cve_2014_0323_rule_5.filter(sensor_list))

    cve_2014_0323_rule_6 = rule_engine.Rule(
        'software_version == "8"'
    )
    filter_cve_2014_0323_rule_6 = tuple(cve_2014_0323_rule_6.filter(sensor_list))

    global medium_threats

    if filter_cve_2014_0323_rule_1:
        if filter_cve_2014_0323_rule_2:
            print("-" * 123)
            print("Sensor Vulnerability found: win32k.sys in the kernel-mode drivers in Windows XP allow local users to"
                  " obtain \nsensitive information from kernel memory or cause a denial of service (system hang) via a "
                  "crafted application, \naka 'Win32k Information Disclosure Vulnerability.'")
            print("*" * 20)
            print("Threat: Total shutdown of sensor meaning data will no longer be available.")
            print("*" * 20)
            print("Threat: There is total information disclosure, resulting in all system files being revealed.")
            print("*" * 20)
            print("Control: Please complete SP2 or SP3 update")
            print("Please see here for further details: https://www.cvedetails.com/cve/CVE-2014-0323/")
            print("*" * 20)
            for sensor in filter_cve_2014_0323_rule_2:
                print("Affected Sensor: ", *sensor['sensor_id'])
                print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                print(*sensor['connected_sensors'], sep=', ')
                print()

            cvss_calc('CVSS:3.0/S:U/C:H/I:L/A:H/AV:L/AC:H/PR:H/UI:R')
            medium_threats += 1
            print("-" * 123)

    if filter_cve_2014_0323_rule_1:
        if filter_cve_2014_0323_rule_3:
            print("-" * 123)
            print("Sensor Vulnerability found: win32k.sys in the kernel-mode drivers in Server 2012 allow local users "
                  "to \nobtain sensitive information from kernel memory or cause a denial of service (system hang) via "
                  "a crafted application,\naka 'Win32k Information Disclosure Vulnerability.'")
            print("*" * 20)
            print("Threat: Total shutdown of sensor meaning data will no longer be available.")
            print("*" * 20)
            print("Threat: There is total information disclosure, resulting in all system files being revealed.")
            print("*" * 20)
            print("Control: Please complete SP1 update")
            print("Please see here for further details: https://www.cvedetails.com/cve/CVE-2014-0323/")
            print("*" * 20)
            for sensor in filter_cve_2014_0323_rule_3:
                print("Affected Sensor: ", *sensor['sensor_id'])
                print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                print(*sensor['connected_sensors'], sep=', ')
                print()

            cvss_calc('CVSS:3.0/S:U/C:H/I:L/A:H/AV:L/AC:H/PR:H/UI:R')
            medium_threats += 1
            print("-" * 123)

    if filter_cve_2014_0323_rule_1:
        if filter_cve_2014_0323_rule_4:
            print("-" * 123)
            print("Sensor Vulnerability found: win32k.sys in the kernel-mode drivers in Windows Vista allow local users"
                  " to obtain \nsensitive information from kernel memory or cause a denial of service (system hang) via"
                  " a crafted application, \naka 'Win32k Information Disclosure Vulnerability.'")
            print("*" * 20)
            print("Threat: Total shutdown of sensor meaning data will no longer be available.")
            print("*" * 20)
            print("Threat: There is total information disclosure, resulting in all system files being revealed.")
            print("*" * 20)
            print("Control: Please complete SP2 update.")
            print("Please see here for further details: https://www.cvedetails.com/cve/CVE-2014-0323/")
            print("*" * 20)
            for sensor in filter_cve_2014_0323_rule_4:
                print("Affected Sensor: ", *sensor['sensor_id'])
                print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                print(*sensor['connected_sensors'], sep=', ')
                print()

            cvss_calc('CVSS:3.0/S:U/C:H/I:L/A:H/AV:L/AC:H/PR:H/UI:R')
            medium_threats += 1
            print("-" * 123)

    if filter_cve_2014_0323_rule_1:
        if filter_cve_2014_0323_rule_5:
            print("-" * 123)
            print("Sensor Vulnerability found: win32k.sys in the kernel-mode drivers in Windows 7 allow local users"
                  "to obtain \nsensitive information from kernel memory or cause a denial of service (system hang) via "
                  "a crafted application, \naka 'Win32k Information Disclosure Vulnerability.'")
            print("*" * 20)
            print("Threat: Total shutdown of sensor meaning data will no longer be available.")
            print("*" * 20)
            print("Threat: There is total information disclosure, resulting in all system files being revealed.")
            print("*" * 20)
            print("Control: Please complete SP1 update.")
            print("Please see here for further details: https://www.cvedetails.com/cve/CVE-2014-0323/")
            print("*" * 20)
            for sensor in filter_cve_2014_0323_rule_5:
                print("Affected Sensor: ", *sensor['sensor_id'])
                print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                print(*sensor['connected_sensors'], sep=', ')
                print()

            cvss_calc('CVSS:3.0/S:U/C:H/I:L/A:H/AV:L/AC:H/PR:H/UI:R')
            medium_threats += 1
            print("-" * 123)

    if filter_cve_2014_0323_rule_1:
        if filter_cve_2014_0323_rule_6:
            print("-" * 123)
            print("Sensor Vulnerability found: win32k.sys in the kernel-mode drivers in Windows 8 allow local users"
                  "to obtain \nsensitive information from kernel memory or cause a denial of service (system hang) via "
                  "a crafted application, \naka 'Win32k Information Disclosure Vulnerability.'")
            print("*" * 20)
            print("Threat: Total shutdown of sensor meaning data will no longer be available.")
            print("*" * 20)
            print("Threat: There is total information disclosure, resulting in all system files being revealed.")
            print("*" * 20)
            print("Control: Please complete SP1 update.")
            print("Please see here for further details: https://www.cvedetails.com/cve/CVE-2014-0323/")
            print("*" * 20)
            for sensor in filter_cve_2014_0323_rule_6:
                print("Affected Sensor: ", *sensor['sensor_id'])
                print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                print(*sensor['connected_sensors'], sep=', ')
                print()

            cvss_calc('CVSS:3.0/S:U/C:H/I:L/A:H/AV:L/AC:H/PR:H/UI:R')
            medium_threats += 1
            print("-" * 123)


def cve_2019_1489():
    cve_2019_1489_rule_1 = rule_engine.Rule(
        'operating_system == "Windows"'
    )
    filter_cve_2019_1489_rule_1 = tuple(cve_2019_1489_rule_1.filter(sensor_list))

    cve_2019_1489_rule_2 = rule_engine.Rule(
        'operating_system == "XP"'
    )
    filter_cve_2019_1489_rule_2 = tuple(cve_2019_1489_rule_2.filter(sensor_list))

    if filter_cve_2019_1489_rule_1:
        if filter_cve_2019_1489_rule_2:
            print("-" * 123)
            print("Sensor vulnerability found: An information disclosure vulnerability exists when the Windows Remote "
                  "Desktop Protocol (RDP)\n fails to properly handle objects in memory, aka 'Remote Desktop Protocol "
                  "Information Disclosure Vulnerability'.")
            print("*" * 20)
            print("Threat: There is considerable informational disclosure.")
            print("*" * 20)
            print("Control: Please complete SP3 update")
            print("Please see here for further details: https://www.cvedetails.com/cve/CVE-2019-1489/")
            print("*" * 20)
            for sensor in filter_cve_2019_1489_rule_2:
                print("Affected Sensor: ", *sensor['sensor_id'])
                print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
                print(*sensor['connected_sensors'], sep=', ')
                print()

            cvss_calc('CVSS:3.0/S:U/C:H/I:L/A:H/AV:L/AC:H/PR:H/UI:R')

            print("-" * 123)


def access_control():
    access_control_rule_1 = rule_engine.Rule(
        'access_control == false'
    )
    filter_access_control_rule_1 = tuple(access_control_rule_1.filter(sensor_list))

    global high_threats

    if filter_access_control_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor does not have access control.")
        print("*" * 20)
        print("Threat: Eavesdropping - Threat actors may be able to passively capture data.")
        print("*" * 20)
        print("Threat: Threat actors may be able to launch other attacks (wormhole, black-hole)")
        print("*" * 20)
        print("Control(s):")
        print("1) Enable access control")
        print("2) Reduce sensed data details")
        print("3) Access restriction")
        print("4) Use strong encryption techniques")
        print("*" * 20)
        for sensor in filter_access_control_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:H/I:L/A:L/AV:L/AC:L/PR:N/UI:R')
        high_threats += 1
        print("-" * 123)


def secure_key_storage():
    secure_key_storage_rule_1 = rule_engine.Rule(
        'secure_key_storage == ["none"]'
    )
    filter_secure_key_storage_rule_1 = tuple(secure_key_storage_rule_1.filter(sensor_list))

    global high_threats

    if filter_secure_key_storage_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Keys not stored in secure element.")
        print("*" * 20)
        print("Threat: A threat actor could use a malicious node to impersonate a valid node using the compromised "
              "keys.")
        print("*" * 20)
        print("Threat: Routing information modification")
        print("*" * 20)
        print("Threat: False sensor readings")
        print("*" * 20)
        print("Threat: Resources exhaustion")
        print("*" * 20)
        print("Threat: Carrying out further attacks to disrupt operation of the WSN")
        print("*" * 20)
        print("Controls(s): Install sensors with secure element.")
        print("*" * 20)
        for sensor in filter_secure_key_storage_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:H/I:H/A:L/AV:P/AC:L/PR:N/UI:R')
        high_threats += 1
        print("-" * 123)


def time_diversity():
    time_diversity_rule_1 = rule_engine.Rule(
        'time_diversity == false'
    )
    filter_time_diversity_rule_1 = tuple(time_diversity_rule_1.filter(sensor_list))

    global high_threats

    if filter_time_diversity_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor not applying time diversity to packet transmission.")
        print("*" * 20)
        print("Threat: Collision of packets between sensors.")
        print("*" * 20)
        print("Threat: Energy exhaustion resulting in DoS from affected sensors")
        print("*" * 20)
        print("Threat: Packet integrity could be compromised")
        print("*" * 20)
        print("Control: Apply time diversity to packet transmissions.")
        print("*" * 20)
        for sensor in filter_time_diversity_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()

        cvss_calc('CVSS:3.0/S:C/C:L/I:H/A:H/AV:N/AC:H/PR:H/UI:R')
        high_threats += 1
        print("-" * 123)


# --------------- stdout redirect --------------------


class Redirect:

    def __init__(self, widget):
        self.widget = widget
        self.geometry = None

    def write(self, text):
        self.widget.insert('end', text)
        # self.widget.see('end') # autoscroll


def pdf_gen():
    file_path = 'randomfile.txt'
    sys.stdout = open(file_path, "w")


def hide(x):
    x.grid_remove()


def show_end(event):
    text.see(tk.END)
    text.edit_modified(0)  # IMPORTANT - or <<Modified>> will not be called later.


# --------------- data ingest--------------------


sensor_list = []

root = tk.Tk()
root.title('WSN Threat Modeller')
root.geometry('1075x500')


def open_file():
    file_path = askopenfile(mode='r', filetypes=[('Text File', '*txt')])
    if file_path is not None:
        pass
    for jsonObj in file_path:
        sensor_dict = json.loads(jsonObj)
        sensor_list.append(sensor_dict)

    # informs if JSON parsed is valid and will print issues if not
    isValid, msg = validate_json(sensor_dict)
    print(msg)

    # ---------------------- UI ------------------------

    pb1 = Progressbar(
        root,
        orient=HORIZONTAL,
        length=300,
        mode='determinate'
    )
    pb1.grid(row=1, column=7, columnspan=1, pady=20)
    for i in range(5):
        root.update_idletasks()
        pb1['value'] += 20
        time.sleep(0.5)
    pb1.destroy()
    Label(root, text='File Uploaded Successfully!', foreground='green').grid(row=1, column=7, columnspan=1, pady=10)


welcome_label = Label(
    root,
    text="Welcome to WSN Threat Modeller"
)
welcome_label.grid(row=0, column=1, columnspan=3, pady=10)

json_label = Label(
    root,
    text='Upload JSON in .txt format '
)
json_label.grid(row=1, column=7)

json_button = Button(
    root,
    text='Choose File',
    command=lambda: open_file()
)
json_button.grid(row=1, column=8)

text = tk.Text(root,
               bg="white",
               fg="black",
               font=("Calibri",
                     12, "bold"),
               borderwidth=4,
               relief='ridge')
text.grid(row=1, columnspan=2)

analyse = tk.Button(root, text='Analyse', command=lambda: [
    introduction(),
    node_capturing_rules(),
    anti_tamper_rules(),
    battery_information_rule(),
    boot_rule(),
    update_rules(),
    routing_protocol_rules(),
    cve_2020_10757(),
    log4j(),
    communication_rules(),
    shared_resources(),
    lorawan(),
    encryption(),
    cve_2021_38386(),
    cve_2014_0323(),
    cve_2019_1489(),
    access_control(),
    secure_key_storage(),
    time_diversity(),
    threat_counter(),
    text.see(tk.END)
])

analyse.grid(row=2, column=0, columnspan=2, pady=10)

pdf = tk.Button(root, text='PDF Report', command=pdf_gen())
pdf.grid(row=3, column=0, columnspan=2)

old_stdout = sys.stdout
sys.stdout = Redirect(text)

root.mainloop()

sys.stdout = old_stdout
