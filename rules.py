import rule_engine
import datetime

comics = [
    {
        'title': 'Batman',
        'publisher': 'DC',
        'issue': 89,
        'released': datetime.date(2020, 4, 28)
    },
    {
        'title': 'Flash',
        'publisher': 'DC',
        'issue': 753,
        'released': datetime.date(2020, 5, 5)
    },
    {
        'title': 'Captain Marvel',
        'publisher': 'Marvel',
        'issue': 18,
        'released': datetime.date(2020, 5, 6)
    }
]

rule = rule_engine.Rule(
    # match books published by DC
    'publisher == "DC"'
)

# check if the first object matches
print(rule.matches(comics[0])) # => True

# filter the iterable "comics" and return matching objects
print(rule.filter(comics)) # => <generator object Rule.filter at 0x7f2bdafbe650>
