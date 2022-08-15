from tkinter import *
from tkinter.ttk import *
from tkinter.filedialog import askopenfile
import time
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


node_capturing_rules()

import_screen = Tk()
import_screen.title('WSN Threat Model Input')
import_screen.geometry('600x400')

analyse = Button(
    import_screen,
    text='Analyse',
    command=lambda: [node_capturing_rules()],
)
analyse.grid(row=5, columnspan=4, pady=10)