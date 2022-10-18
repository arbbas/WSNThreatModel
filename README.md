# WSN Threat Modeller

WSN Threat Modeller is a threat modelling tool that is focused on 
wireless sensor networks. This is a proof of concept tool that is able 
to identify some of the main threat that WSNs face in the current threat landscape.

Users are welcome to extend the JSON schema to better suit the needs of their network and can 
also write new threats into the programme should they need to.

# Usage Guidance and Help


Please make a model of a wireless sensor network using the template below. 
 WSN configuration files should be in the .txt format. Configurations can be heterogeneous to facilitate many types of WSNs.

To start the tool, please run the python file from you chosen CLI.

The tool will then open with a blank reporting page available. Please click
the upload button and select the config file in .txt format made previously.

You will receive a system notification once the file is uploaded and JSON data
is validated. Should the data not be valid, the report will show which section
of the config file has the issue.

Please then click analyse to generate the report. The report will contain 
a summary along with identified threats within your system model.

# Data Model Template

Below is the modelling template. Each field relates to JSON data. There is a 
JSON Schema within the project to refer to when building the model for data types 
and amount of data each field can take. Any field with [] is an array and will
take multiple arguments. Any fields with " " will take one argument.

Please delimit any config files with a comma between each sensor node data set
(one has been placed at the end of the template for ease of copy/paste).

{"sensor_id": [input here], "connection_type": ["input here"], "ip_address": "input here", "mac_address": "input here", "hardware_interface": ["input here"], "network_routing_protocols": ["input here"], "connected_sensors": ["input here"], "protocol_version": ["input here"], "operating_system": "input here", "software_version": "input here", "firmware_version": "input here", "interfaces": ["input here"], 
"administration": "input here", "update_process": "input here", "reset_functionality": input here, "shared_resources": input here, "secure_key_storage": ["input here"], "data_storage": input here, "power_consumption": "input here", "electromagnetic_emission": "input here", "encryption": ["input here"], "authentication": ["input here"], "input_sanitisation": ["input here"], "bandwidth": "input here", "throughput": "input here", "latency": "input here", "error_rate": "input here", "anti_tamper_destruction": input here, "accessible_battery_data": input here, "secure_boot": input here, "dependencies": ["input here"], "access_control": input here, "time_diversity": input here},

