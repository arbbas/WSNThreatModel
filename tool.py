import json
import jsonschema
from jsonschema import validate
from jsonschema import Draft202012Validator
import rule_engine


# class Sensor(object):
#     def __init__(self, sensor_id, ip_address, mac_address, hardware_interface, connection_type,
#                  network_protocols, protocol_version, pairing_process, secure_key_storage,
#                  data_storage, power_consumption, electromagnetic_emission, operating_system,
#                  software_version, firmware_version, interfaces, administration, update_process,
#                  reset_functionality, shared_resources, connected_sensors, encryption, authentication,
#                  input_sanitisation, bandwidth, throughput, latency, error_rate):
#         self.sensor_id = sensor_id
#         self.ip_address = ip_address
#         self.mac_address = mac_address
#         self.hardware_interface = hardware_interface
#         self.connection_type = connection_type
#         self.network_protocols = network_protocols
#         self.protocol_version = protocol_version
#         self.pairing_process = pairing_process
#         self.secure_key_storage = secure_key_storage
#         self.data_storage = data_storage
#         self.power_consumption = power_consumption
#         self.electromagnetic_emission = electromagnetic_emission
#         self.operating_system = operating_system
#         self.software_version = software_version
#         self.firmware_version = firmware_version
#         self.interfaces = interfaces
#         self.administration = administration
#         self.update_process = update_process
#         self.reset_functionality = reset_functionality
#         self.shared_resources = shared_resources
#         self.connected_sensors = connected_sensors
#         self.encryption = encryption
#         self.authentication = authentication
#         self.input_sanitisation = input_sanitisation
#         self.bandwidth = bandwidth
#         self.throughput = throughput
#         self.latency = latency
#         self.error_rate = error_rate


# class Network(object):
#     def __init__(self, encryption, authentication, input_sanitisation,
#                  bandwidth, throughput, latency, error_rate):
#         self.encryption = encryption
#         self.authentication = authentication
#         self.input_sanitisation = input_sanitisation
#         self.bandwidth = bandwidth
#         self.throughput = throughput
#         self.latency = latency
#         self.error_rate = error_rate


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


sensorList = []

with open('input.txt', 'r', encoding='utf-8') as inp:
    for jsonObj in inp:
        sensorDict = json.loads(jsonObj)
        sensorList.append(sensorDict)

isValid, msg = validate_json(sensorDict)
print(msg)


# sensor_1 = sensorList[0]
# sensor_1_obj = Sensor(**sensor_1)
# sensors.append(sensor_1_obj)
# sensor_2 = sensorList[1]
# sensor_2_obj = Sensor(**sensor_2)
# sensor_3 = sensorList[2]
# sensor_3_obj = Sensor(**sensor_3)
# sensor_4 = sensorList[3]
# sensor_4_obj = Sensor(**sensor_4)
# sensor_5 = sensorList[4]
# sensor_5_obj = Sensor(**sensor_5)


def node_capturing_rules():
    node_rule_1 = rule_engine.Rule(
        'data_storage == true'
    )

    filter_1 = node_rule_1.filter(sensorList)

    print("-" * 100)
    print("Sensor vulnerability found: Data stored on device")
    print()
    print("Threat: Node capturing - if node captured data might be obtained by an adversary")
    print()
    print("Control: Please make sure data is encrypted if possible")
    print()
    print("Affected Sensors:")
    for sensor in filter_1:
        print(sensor['sensor_id'])

    print("-" * 100)


def anti_tamper_rules():
    at_rule_1 = rule_engine.Rule(
        'anti_tamper_destruction == false'
    )

    filter_1 = at_rule_1.filter(sensorList)

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
    print("Affected Sensors:")
    for sensor in filter_1:
        print(sensor['sensor_id'])

    print("-" * 100)


def battery_information_rule():
    battery_rule_1 = rule_engine.Rule(
        'accessible_battery_data == false'
    )

    filter_1 = battery_rule_1.filter(sensorList)

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
    print("Affected Sensors:")
    for sensor in filter_1:
        print(sensor['sensor_id'])

    print("-" * 100)


def communication_rules():
    comm_rule_1 = rule_engine.Rule(
         'connection_type == "MiWi'
     )
    filter = comm_rule_1.filter(sensorList)

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
    print("Affected Sensors:")
    for sensor in filter:
        print(sensor['sensor_id'])

    print("-" * 100)


node_capturing_rules()
anti_tamper_rules()
battery_information_rule()
