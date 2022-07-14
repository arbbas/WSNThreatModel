import json
import jsonschema
import pprint
from jsonschema import validate
from jsonschema import Draft202012Validator
from collections import namedtuple
from json import JSONEncoder


class Sensor(object):
    def __init__(self, sensor_id, ip_address, mac_address, hardware_interface, connection_type,
                 network_protocols, protocol_version, pairing_process, secure_key_storage,
                 data_storage, power_consumption, electromagnetic_emission, operating_system,
                 software_version, firmware_version, interfaces, administration, update_process,
                 reset_functionality, shared_resources, connected_sensors, encryption, authentication,
                 input_sanitisation, bandwidth, throughput, latency, error_rate):
        self.sensor_id = sensor_id
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.hardware_interface = hardware_interface
        self.connection_type = connection_type
        self.network_protocols = network_protocols
        self.protocol_version = protocol_version
        self.pairing_process = pairing_process
        self.secure_key_storage = secure_key_storage
        self.data_storage = data_storage
        self.power_consumption = power_consumption
        self.electromagnetic_emission = electromagnetic_emission
        self.operating_system = operating_system
        self.software_version = software_version
        self.firmware_version = firmware_version
        self.interfaces = interfaces
        self.administration = administration
        self.update_process = update_process
        self.reset_functionality = reset_functionality
        self.shared_resources = shared_resources
        self.connected_sensors = connected_sensors
        self.encryption = encryption
        self.authentication = authentication
        self.input_sanitisation = input_sanitisation
        self.bandwidth = bandwidth
        self.throughput = throughput
        self.latency = latency
        self.error_rate = error_rate


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


sensors = []
sensorList = []

with open('input.txt', 'r', encoding='utf-8') as inp:
    for jsonObj in inp:
        sensorDict = json.loads(jsonObj)
        sensorList.append(sensorDict)

isValid, msg = validate_json(sensorDict)
print(msg)

sensor_1 = sensorList[0]
sensor_1_obj = Sensor(**sensor_1)
sensor_2 = sensorList[1]
sensor_2_obj = Sensor(**sensor_2)
sensor_3 = sensorList[2]
sensor_3_obj = Sensor(**sensor_3)
sensor_4 = sensorList[3]
sensor_4_obj = Sensor(**sensor_4)
sensor_5 = sensorList[4]
sensor_5_obj = Sensor(**sensor_5)

print(sensor_1_obj.ip_address)
print(sensor_2_obj.authentication)

# for i in sensorList:
#     sensor_a = sensorList[i]
#     sensors = Sensor(**sensor_a)
#     print(sensors)