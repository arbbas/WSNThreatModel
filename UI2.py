import json
import tkinter as tk
import time
from tkinter import ttk, HORIZONTAL
from tkinter import *
from tkinter.filedialog import askopenfile
from tkinter.ttk import Progressbar
import json
import jsonschema
from jsonschema import validate
from jsonschema import Draft202012Validator
import rule_engine
from cvss import CVSS3
from tool import *


# -------- functions ---------


def cvss_calc(vector):
    print()
    print("Vulnerability level:")
    print()
    c = CVSS3(vector)
    print(c.clean_vector())
    print("Base vulnerability score: ", c.base_score)
    sev = c.severities()
    print("Vulnerability level: ", sev[0])


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


def hide(x):
    x.grid_remove()


sensor_list = []


def open_file():
    file_path = askopenfile(mode='r', filetypes=[('Text File', '*txt')])
    if file_path is not None:
        pass
    for jsonObj in file_path:
        sensor_dict = json.loads(jsonObj)
        sensor_list.append(sensor_dict)
    print(sensor_list)

    isValid, msg = validate_json(sensor_dict)
    ttk.Label(text=msg)

    # pb1 = Progressbar(
    #     orient=HORIZONTAL,
    #     length=300,
    #     mode='determinate'
    # )
    # pb1.grid(row=4, columnspan=3, pady=20)
    # for i in range(5):
    #     if pb1['value'] < 100:
    #         pb1['value'] += 20
    #         time.sleep(1)
    #     else:
    #         pb1.destroy()
    #         ttk.Label(text='File Uploaded Successfully!', foreground='green').grid(row=4, columnspan=3, pady=10)


def generate_report():
    label = ttk.Label(master=None, text=lambda: [node_capturing_rules(),
                                                 anti_tamper_rules(),
                                                 battery_information_rule(),
                                                 boot_rule(),
                                                 update_rules(),
                                                 routing_protocol_rules(),
                                                 cve_2020_10757(),
                                                 log4j(),
                                                 communication_rules()])
    label.pack()


# --------- classes ----------

class ThreatModellingTool(tk.Tk):
    """
    This class is created to initialise the pages of the application
    """

    # init function for the threat modelling tool
    def __init__(self, *args, **kwargs):
        # init function for the Tk class
        tk.Tk.__init__(self, *args, *kwargs)

        # creating the container
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)

        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        # Create and array to initialise the frames(pages)
        self.pages = {}

        # looping over a tuple with the page layouts
        for Page in (UploadPage, HelpPage, AnalysePage):
            page = Page(container, self)

            # initialise the page object from UploadPage, HelpPage, AnalysePage
            self.pages[Page] = page

            page.grid(row=0, column=0, sticky="nsew")

        self.show_page(UploadPage)

    # function to show the current page as parameter
    def show_page(self, cont):
        page = self.pages[cont]
        page.tkraise()


class UploadPage(tk.Frame):
    """
    This class is to layout the upload page
    """

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        button1 = ttk.Button(self, text="Help Page",
                             command=lambda: controller.show_page(HelpPage))

        # putting the button in its place by
        # using grid
        button1.grid(row=4, column=0, padx=10, pady=10)

        # button to show frame 2 with text layout2
        button2 = ttk.Button(self, text="Analyse Data",
                             command=lambda: controller.show_page(AnalysePage))

        # putting the button in its place by
        # using grid
        button2.grid(row=4, column=4, padx=10, pady=10)

        welcome_label = ttk.Label(self, text="Welcome to WSN Threat Modeller")
        welcome_label.grid(row=0, column=1, padx=10)

        file_label = ttk.Label(self, text="Upload JSON in .txt format.")
        file_label.grid(row=2, column=0, padx=10)

        file_upload_button = ttk.Button(self, text="Choose File",
                                        command=lambda: open_file()
                                        )
        file_upload_button.grid(row=2, column=1)


# second window frame page1
class HelpPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = ttk.Label(self, text="Help Page")
        label.grid(row=0, column=4, padx=10, pady=10)

        # button to show frame 2 with text
        # layout2
        button1 = ttk.Button(self, text="Upload Page",
                             command=lambda: controller.show_page(UploadPage))

        # putting the button in its place
        # by using grid
        button1.grid(row=1, column=1, padx=10, pady=10)

        # button to show frame 2 with text
        # layout2
        button2 = ttk.Button(self, text="Analyse Data Page",
                             command=lambda: controller.show_page(AnalysePage))

        # putting the button in its place by
        # using grid
        button2.grid(row=2, column=1, padx=10, pady=10)


# third window frame page2
class AnalysePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = ttk.Label(self, text="Analyse Page")
        label.grid(row=0, column=4, padx=10, pady=10)

        # button to show frame 2 with text
        # layout2
        button1 = ttk.Button(self, text="Help Page",
                             command=lambda: controller.show_page(HelpPage))

        # putting the button in its place by
        # using grid
        button1.grid(row=2, column=1, padx=10, pady=10)

        # button to show frame 3 with text
        # layout3
        button2 = ttk.Button(self, text="Upload Page",
                             command=lambda: controller.show_page(UploadPage))

        # putting the button in its place by
        # using grid
        button2.grid(row=2, column=1, padx=10, pady=10)

        button_3 = ttk.Button(self, text="Analyse", command=generate_report())
        button_3.grid(row=1, column=1)

        report_label = ttk.Label(self, text='')
        report_label.grid(row=2, column=2)


# Driver Code
app = ThreatModellingTool()
app.mainloop()
