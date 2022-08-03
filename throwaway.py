
from tkinter import *
import random

#Lists of words that will be used by the generate_name() function

wordclass1 = (
    'word1',
    'word2',
    'word3',
)

wordclass2 = (
    'word4',
    'word5',
    'word6',
)

wordclass3 = (
    'word7',
    'word8',
    'word9',
)

#These functions do the actual random generation of the names.

def name1():
    full_name = random.choice(wordclass1) + " " + random.choice(wordclass2)
    return full_name

def name2():
    full_name = random.choice(wordclass2) + " " + random.choice(wordclass3)
    return full_name

def name3():
    full_name = random.choice(wordclass1) + " " + random.choice(wordclass2) + " " + random.choice(wordclass3)
    return full_name

#This function randomly picks the individual name that should be displayed on the tkinter label

def generate_name():
    return random.choice([name1, name2, name3])()

#This function is supposed to display the text on the tkinter label

def write():
    label.config(text=generate_name())

root = Tk()

label = Label(root, text='')
label.pack()
button = Button(root, text="Generate a name!", command=write)
button.pack()

root.mainloop()