#!/usr/bin/env python3
from defusedxml.ElementTree import *
import sys

if len(sys.argv) < 2:
    print("$ ./xmlparsing_test.py <file name> [Optional -b to break after first flaw]")
    sys.exit(1)
else:
    xmlFile = sys.argv[1] 
    if len(sys.argv) == 3:
        breakP = True
    else:
        breakP = False

et = parse(xmlFile)
root = et.getroot()

attribs = ["cwe_id", "cvss", "capec_id", "count"]
flawParts = ["name","description", "remediationeffort",
             "remediation_desc", "exploit_desc", "severity_desc",
             "note", "input_vector", "location", "exploit_difficulty",
             "appendix/"]
count = 0 

# How to remove attributes from a tag.
if root.attrib["assurance_level"]:
    root.attrib.pop("assurance_level", None)
    print("[*]  Assurance_level was deleted!")

# Iterating the flaws
for flaw in root.iter("{http://www.veracode.com/schema/import}flaw"):

    count = count + 1
    
    for x in attribs:
        if flaw.attrib[x] == "" or flaw.attrib[x] == "0":
            print("\t- {} is missing.".format(x))
        #else:    
        #    print("Flaw Attribute {}: {}".format(x, flaw.attrib[x]))
    
    for x in flawParts:
    
        head = ".//{http://www.veracode.com/schema/import}"
        if x == "appendix/": x = "description"
        head = head + x
        
        if flaw.find(head).text == None:
            if x == "name":
                print("\t- Flaw #{} is missing a name".format(count))
            else:
                print("\t- {} is missing".format(x))
        
        #else:
        #    print("Flaw Part {}:\n\t- {}".format(x, flaw.find(head).text))
    print()
    
    if breakP:
        break
