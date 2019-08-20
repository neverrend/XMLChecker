#!/usr/bin/env python3
from defusedxml.ElementTree import *
from xml.etree.ElementTree import register_namespace
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
        root = xmlFile.getroot()

        attribs = ["cwe_id", "cvss", "capec_id", "count"]
        flawParts = ["name","description", "remediationeffort",
                     "remediation_desc", "exploit_desc", "severity_desc",
                     "note", "input_vector", "location", "exploit_difficulty",
                     "appendix/"]
        count = 0
        for flaw in root.iter("{http://www.veracode.com/schema/import}flaw"):
            count = count + 1
            instanceNum = 0
            
            flawProps = copy.deepcopy(self.flawProps)

            for attrib in attribs:
                if attrib == "cwe_id": flawProps["Flaw CWE"] = flaw.attrib[attrib]
                if attrib == "cvss": flawProps["Flaw CVSS"] = flaw.attrib[attrib]
                if attrib == "capec_id": flawProps["Flaw CAPEC"] = flaw.attrib[attrib]
                if attrib == "count" : flawProps["Flaw Count"] = flaw.attrib[attrib]
        
            for part in flawParts:
                head = ".//{http://www.veracode.com/schema/import}"
                head = head + part
                if part == "name": 
                    flawProps["Flaw Name"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "description": 
                    flawProps["Flaw Description"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "remediationeffort": 
                    flawProps["Flaw Remediation Effort"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "remediation_desc": 
                    flawProps["Flaw Remediation"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "exploit_desc": 
                    flawProps["Flaw Exploit Description"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "severity_desc": 
                    flawProps["Flaw Severity Description"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "note": 
                    flawProps["Flaw Note"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "input_vector": 
                    flawProps["Flaw Input Vector"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "location": 
                    flawProps["Flaw Location"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "exploit_difficulty": 
                    flawProps["Flaw Exploit Difficulty"] = flaw.find(head).text \
                            if flaw.find(head) != None else ""
                if part == "appendix/": flawProps["Flaw Appendix"]["Appendix Description"] = \
                            flaw.find(head).text if flaw.find(head) != None else "" 

            for appendix in flaw.findall(".//{http://www.veracode.com/schema/import}appendix"):
                for code in appendix.findall(".//{http://www.veracode.com/schema/import}code"):
                    if code.text == None:
                        continue
                    else:
                        instanceNum = instanceNum + 1
                        flawProps["Flaw Appendix"]["Instance #"+str(instanceNum)] = code.text \
                                if code.text != None else ""
            
            flawProps["Flaw Appendix"]["Instance Count"] = instanceNum
            self.flaws["Flaw #"+str(count)] = copy.deepcopy(flawProps)
            
            #print(json.dumps(self.flaws, indent=4))
            #if count == 2: break

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
                    print("[*]\t Flaw Counts/Instance Count: ({}/{})".format(self.flaws[flaw]["Flaw Count"],\
                            self.flaws[flaw]["Flaw Appendix"]["Instance Count"]))
                elif name == "CVSS":
                    digits = re.compile("([\d\.]{3})")
                    cvssNum = digits.search(self.flaws[flaw]["Flaw Note"]).group()
                    if float(self.flaws[flaw]["Flaw "+name]) != float(cvssNum):
                        print("[*]\t Flaw CVSS score({}) doesnt match the Note score({})."\
                                .format(self.flaws[flaw]["Flaw "+name],cvssNum))
                elif name == "Location":
                    if len(self.flaws[flaw]["Flaw "+name]) > 255:
                        print("[*]\t Flaw Location size is too large.")

            print()

    
    def cruftRemoval(self, root):
        codeStr = ".//{http://www.veracode.com/schema/import}code"
        chklstStr = ".//{http://www.veracode.com/schema/import}checklistflaws"
        chklst = root.find(chklstStr)
        if len(root.attrib) == 5:
            root.attrib.pop("assurance_level", None)
        
        if root.findall(chklstStr):
            root.remove(chklst)  

        for appendix in root.findall(".//{http://www.veracode.com/schema/import}appendix"):
            for code in appendix.findall(codeStr):
                if code.text == None:
                    appendix.remove(code)

        print("[*]\t Cruft Removed from XML file.")
    

def writeToXML(xmlFile, et):
    newFile = "NEW_" + xmlFile
    with open(newFile, "w") as f:
        xmlString = tostring(et.getroot(), encoding="unicode", method="xml")
        f.write(xmlString)

    print("\n[*]\t Changes have been written to: {}".format(newFile))

    

def main():
    if len(sys.argv) < 2:
        print("$ ./xmlparsing_test.py <file name>")
        sys.exit(1)
    else:
        xmlFile = sys.argv[1] 

    register_namespace("", "http://www.veracode.com/schema/import")
    
    et = parse(xmlFile)

    newFile = xmlReport()
    newFile.processFlaws(et)
    newFile.Analyze()

    print("="*50+"\n")
   
    newFile.cruftRemoval(et.getroot())
    writeToXML(xmlFile, et)
    
if __name__ == "__main__":
    main()
