#!/usr/bin/env python3
from defusedxml.ElementTree import *
import copy
import json
import re
import sys

class xmlReport:
    def __init__(self):
        self.flawProps = {
                        "Flaw Name":"",
                        "Flaw CWE" : "",
                        "Flaw CVSS" : "",
                        "Flaw CAPEC" : "",
                        "Flaw Count" : "",
                        "Flaw Description" : "",
                        "Flaw Remediation" : "",
                        "Flaw Remediation Effort" : "",
                        "Flaw Exploit Description" : "",
                        "Flaw Severity Description" : "",
                        "Flaw Note" : "",
                        "Flaw Input Vector" : "",
                        "Flaw Location" : "",
                        "Flaw Exploit Difficulty" : "",
                        "Flaw Appendix" : { 
                                "Appendix Description" : "",
                                }
                        }
        self.flaws = {}

    def processFlaws(self, xmlFile):
        xml = xmlFile
        root = xml.getroot()

        attribs = ["cwe_id", "cvss", "capec_id", "count"]
        flawParts = ["name","description", "remediationeffort",
                     "remediation_desc", "exploit_desc", "severity_desc",
                     "note", "input_vector", "location", "exploit_difficulty",
                     "appendix/"]
        count = 0
        for flaw in root.iter("{http://www.veracode.com/schema/import}flaw"):
            count = count + 1
            instanceNum = 0
            for attrib in attribs:
                if attrib == "cwe_id": self.flawProps["Flaw CWE"] = flaw.attrib[attrib]
                if attrib == "cvss": self.flawProps["Flaw CVSS"] = flaw.attrib[attrib]
                if attrib == "capec_id": self.flawProps["Flaw CAPEC"] = flaw.attrib[attrib]
                if attrib == "count" : self.flawProps["Flaw Count"] = flaw.attrib[attrib]
        
            for part in flawParts:
                head = ".//{http://www.veracode.com/schema/import}"
                head = head + part
                if part == "name": 
                    self.flawProps["Flaw Name"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "description": 
                    self.flawProps["Flaw Description"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "remediationeffort": 
                    self.flawProps["Flaw Remediation Effort"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "remediation_desc": 
                    self.flawProps["Flaw Remediation"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "exploit_desc": 
                    self.flawProps["Flaw Exploit Description"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "severity_desc": 
                    self.flawProps["Flaw Severity Description"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "note": 
                    self.flawProps["Flaw Note"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "input_vector": 
                    self.flawProps["Flaw Input Vector"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "location": 
                    self.flawProps["Flaw Location"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "exploit_difficulty": 
                    self.flawProps["Flaw Exploit Difficulty"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "appendix/": self.flawProps["Flaw Appendix"]["Appendix Description"] = \
                            flaw.find(head).text if flaw.find(head) != None else "" 

            for code in flaw.findall(".//{http://www.veracode.com/schema/import}code"):
                instanceNum = instanceNum + 1
                self.flawProps["Flaw Appendix"]["Instance #"+str(instanceNum)] = code.text \
                        if code.text != None else ""

            self.flawProps["Flaw Appendix"]["Instance Count"] = instanceNum
            self.flaws["Flaw #"+str(count)] = copy.deepcopy(self.flawProps)
        #    break
        #print(json.dumps(self.flaws, indent=4))

    def Analyze(self):
        names = ["Name", "CWE", "Count", "CAPEC", "CVSS", "Description",
                    "Remediation", "Remediation Effort", "Exploit Description",
                    "Severity Description", "Note", "Input Vector", "Location",
                    "Exploit Difficulty"]
        for flaw in self.flaws:
            print("{}: {}".format(flaw, self.flaws[flaw]["Flaw Name"]))
            for name in names:
                if self.flaws[flaw]["Flaw "+name] == None or \
                    self.flaws[flaw]["Flaw "+name] == "":
                    print("[*]\t Flaw {} is missing.".format(name))
                elif name == "Count":
                    print("[*]\t Counts/Instance Count: ({}/{})".format(self.flaws[flaw]["Flaw Count"],\
                            self.flaws[flaw]["Flaw Appendix"]["Instance Count"]))
                elif name == "CVSS":
                    digits = re.compile("([\d\.]{3})")
                    cvssNum = digits.search(self.flaws[flaw]["Flaw Note"]).group()
                    if float(self.flaws[flaw]["Flaw "+name]) != float(cvssNum):
                        print("[*]\t Flaw CVSS score({}) doesnt match the Note score({})"\
                                .format(self.flaws[flaw]["Flaw "+name],cvssNum))
                            

            print()

def main():
    if len(sys.argv) < 2:
        print("$ ./xmlparsing_test.py <file name>")
        sys.exit(1)
    else:
        xmlFile = sys.argv[1] 

    et = parse(xmlFile)

    newFile = xmlReport()

    newFile.processFlaws(et)

    newFile.Analyze()
    
if __name__ == "__main__":
    main()
