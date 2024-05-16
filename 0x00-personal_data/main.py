#!/usr/bin/env python3
""" doc doc doc """


filter_datum = __import__("filtered_logger").filter_datum

fields = ["password", "date_of_birth"]
messages = [
    2
]

for message in messages:
    print(filter_datum(fields, "xxx", message, ";"))