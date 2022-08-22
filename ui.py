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


def cvss_calc(vector):
    print()
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
        print("-" * 123)
        print('Sensor vulnerability found: ',
              "\n\nData stored on device\n")
        print("*" * 20)
        print("Threat: ",
              "\n\nNode capturing - if node captured data might be obtained by an adversary.\n")
        print("*" * 20)
        print("Control(s): ", "\n\nPlease make sure data on device is encrypted if possible.\n")
        print("*" * 20)
        for sensor in filter_node_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()
        print("-" * 123)


def anti_tamper_rules():
    at_rule_1 = rule_engine.Rule(
        'anti_tamper_destruction == false'
    )

    filter_at_rule_1 = tuple(at_rule_1.filter(sensor_list))

    if filter_at_rule_1:
        print("-" * 123)
        print("Sensor vulnerability found: Sensor not tamper proof")
        print("*" * 20)
        print("Threat: \n\nNode capturing - if node captured data might be obtained by an adversary.\n")
        print("*" * 20)
        print("Threat: \n\nDenial of Service Attack - Should the sensor be a cluster head, "
              "this may cause data to not reach the sink. Data from \nimportant sensors"
              " may also be lost.\n")
        print("*" * 20)
        print("Control(s): \n\nInstall a sensor with a secure element that has a tamper resistance mechanism.\n")
        print("*" * 20)
        for sensor in filter_at_rule_1:
            print("Affected Sensor: ", *sensor['sensor_id'])
            print("Connected sensors to sensor {0} that may be at risk:".format(*sensor['sensor_id']), end=' ')
            print(*sensor['connected_sensors'], sep=', ')
            print()
        print("-" * 123)


def battery_information_rule():
    battery_rule_1 = rule_engine.Rule(
        'accessible_battery_data == false'
    )

    filter_battery_rule_1 = tuple(battery_rule_1.filter(sensor_list))

    if filter_battery_rule_1:
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

        print("-" * 123)


def boot_rule():
    boot_rule_1 = rule_engine.Rule(
        'secure_boot == false'
    )

    filter_boot_rule_1 = tuple(boot_rule_1.filter(sensor_list))

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

        print("-" * 123)

    if filter_update_rule_2:
        global medium_threats
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

                print("-" * 123)


def log4j():
    log4j_rule = rule_engine.Rule(
        'dependencies == ["log4j"]'
    )

    filter_log4j_rule = tuple(log4j_rule.filter(sensor_list))

    if filter_log4j_rule:
        global critical_threats
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
    threat_counter()
])

analyse.grid(row=2, column=0, columnspan=2, pady=10)

pdf = tk.Button(root, text='PDF Report', command=pdf_gen())
pdf.grid(row=3, column=0, columnspan=2)

old_stdout = sys.stdout
sys.stdout = Redirect(text)

root.mainloop()

sys.stdout = old_stdout
