import json
import jsonschema
from jsonschema import validate
from jsonschema import Draft202012Validator
import rule_engine
from cvss import CVSS3


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
        print("-" * 100)
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

        print("-" * 100)


def anti_tamper_rules():
    at_rule_1 = rule_engine.Rule(
        'anti_tamper_destruction == false'
    )

    filter_at_rule_1 = at_rule_1.filter(sensor_list)

    print("-" * 100)
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

    print("-" * 100)


def battery_information_rule():
    battery_rule_1 = rule_engine.Rule(
        'accessible_battery_data == false'
    )

    filter_battery_rule_1 = battery_rule_1.filter(sensor_list)

    print("-" * 100)
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

    print("-" * 100)


def communication_rules():
    comm_rule_1 = rule_engine.Rule(
        'connection_type == "MiWi"'
    )
    filter_comm_rule_1 = comm_rule_1.filter(sensor_list)

    print("-" * 100)
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

    print("-" * 100)


def boot_rule():
    boot_rule_1 = rule_engine.Rule(
        'secure_boot == false'
    )

    filter_boot_rule_1 = boot_rule_1.filter(sensor_list)

    print("-" * 100)
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
        print("-" * 100)
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

        print("-" * 100)

    if filter_update_rule_2:
        print("-" * 100)
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

        print("-" * 100)


def routing_protocol_rules():
    routing_rule_1 = rule_engine.Rule(
        'network_routing_protocols == ["LEACH"]'
    )

    filter_routing_rule_1 = tuple(routing_rule_1.filter(sensor_list))

    if filter_routing_rule_1:
        print("-" * 100)
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


def os_rules():
    node_rule_1 = rule_engine.Rule(
        'data_storage == true'
    )

    filter_node_rule_1 = tuple(node_rule_1.filter(sensor_list))

    ubuntu_rule_1 = rule_engine.Rule(
        'operating_system == "Ubuntu"'
    )

    filter_os_rule_1 = tuple(ubuntu_rule_1.filter(sensor_list))

    ubuntu_version_rule_1 = rule_engine.Rule(
        'software_version == "16.4"'
    )

    filter_os_rule_2 = tuple(ubuntu_version_rule_1.filter(sensor_list))

    ubuntu_version_rule_2 = rule_engine.Rule(
        'software_version == 18.04'
    )

    filter_os_rule_3 = tuple(ubuntu_version_rule_2.filter(sensor_list))

    ubuntu_version_rule_3 = rule_engine.Rule(

    )

    if filter_node_rule_1:
        if filter_os_rule_1:
            if filter_os_rule_2:
                print("Hello")




node_capturing_rules()
anti_tamper_rules()
battery_information_rule()
boot_rule()
update_rules()
routing_protocol_rules()
os_rules()