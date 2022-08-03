from tkinter import *
from tkinter.ttk import *
from tkinter.filedialog import askopenfile
import time
from tool import *

import_screen = Tk()
import_screen.title('WSN Threat Model Input')
import_screen.geometry('600x400')


def analyze():
    analyse = Tk()
    analyse.title('analyse')
    analyse.geometry('600x400')


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

    pb1 = Progressbar(
        import_screen,
        orient=HORIZONTAL,
        length=300,
        mode='determinate'
    )
    pb1.grid(row=4, columnspan=3, pady=20)
    for i in range(5):
        import_screen.update_idletasks()
        pb1['value'] += 20
        time.sleep(1)
    pb1.destroy()
    Label(import_screen, text='File Uploaded Successfully!', foreground='green').grid(row=4, columnspan=3, pady=10)


welcome_label = Label(
    import_screen,
    text="Welcome to WSN Threat Modeller"
)
welcome_label.grid(row=0, column=1, padx=10)

json_label = Label(
    import_screen,
    text='Upload JSON in .txt format '
)
json_label.grid(row=2, column=0, padx=10)

json_button = Button(
    import_screen,
    text='Choose File',
    command=lambda: open_file()
)
json_button.grid(row=2, column=1)



analyse = Button(
    import_screen,
    text='Analyse',
    command=lambda: [node_capturing_rules(), anti_tamper_rules(), battery_information_rule(),
                     boot_rule(),
                     update_rules(),
                     routing_protocol_rules(),
                     cve_2020_10757(),
                     log4j(),
                     communication_rules(), analyze()],
)
analyse.grid(row=5, columnspan=4, pady=10)


import_screen.mainloop()