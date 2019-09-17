#!/usr/bin/env python3
from defusedxml.ElementTree import *
from xml.etree.ElementTree import register_namespace
import base64
import copy
import json
import os
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
                        appendix.remove(code)
                    else:
                        instanceNum = instanceNum + 1
                        flawProps["Flaw Appendix"]["Instance #"+str(instanceNum)] = code.text \
                                if code.text != None else ""
                for screenshot in appendix.findall(".//{http://www.veracode.com/schema/import}screenshot"):
                    #print(screenshot.attrib)
                    if screenshot.attrib["format"] == "undefined":
                        #print(screenshot.attrib["format"])
                        for data in screenshot.findall(".//{http://www.veracode.com/schema/import}data"):
                            #print(data.text)
                            mime = checkImg(data.text)
                            screenshot.attrib["format"] = mime
            
            flawProps["Flaw Appendix"]["Instance Count"] = instanceNum
            self.flaws["Flaw #"+str(count)] = copy.deepcopy(flawProps)
            
            #print(json.dumps(self.flaws, indent=4))
            #if count == 2: break

    def Analyze(self):
        names = ["Name", "CWE", "Count", "CAPEC", "CVSS", "Description",
                    "Remediation", "Remediation Effort", "Exploit Description",
                    "Severity Description", "Note", "Input Vector", "Location",
                    "Exploit Difficulty"]

        digits = re.compile("([\d]+)")
        repoSteps = re.compile("Reproduction Steps\\n([=]*\\n|)([a-zA-Z0-9.!@#$%^&*()_+\-=~`{}[\]\\\|{}:;'\",.<>/?\\n\s\\t]*)\\nThe REQUEST is:")

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
                    nums = re.compile("([\d\.]{3})")
                    cvssNum = nums.search(self.flaws[flaw]["Flaw Note"]).group()
                    if float(self.flaws[flaw]["Flaw "+name]) != float(cvssNum):
                        print("[*]\t Flaw CVSS score({}) doesnt match the Note score({})."\
                                .format(self.flaws[flaw]["Flaw "+name],cvssNum))
                elif name == "Location":
                    if len(self.flaws[flaw]["Flaw "+name]) > 255:
                        print("[*]\t Flaw Location size is too large.")
            
            for x in range(int(self.flaws[flaw]["Flaw Appendix"]["Instance Count"])):
                inst = repoSteps.search(self.flaws[flaw]["Flaw Appendix"]["Instance #"+str(x+1)])
                group = []
                
                if inst:
                    repoBlock = inst.group(2)
                    repoLines = repoBlock.splitlines()
                    #print(repoLines)     
                    
                    for line in repoLines:
                        for index in range(len(repoLines)):
                            if digits.search(line[:3]):
                                group.append(int(digits.search(line[:3]).group()))
                                break
                #print(group)

                if len(group) > 1 and not checkConsecutive(group):
                    print("[*]\t Instance #{} has misnumbered steps.".format(x+1))
                    #print(group)
            #break

            print()


    def cruftRemoval(self, root):
        codeStr = ".//{http://www.veracode.com/schema/import}code"
        chklstStr = ".//{http://www.veracode.com/schema/import}checklistflaws"
        chklst = root.find(chklstStr)
        if len(root.attrib) == 5:
            root.attrib.pop("assurance_level", None)
        
        if root.findall(chklstStr):
            root.remove(chklst)  

        print("[*]\t Cruft Removed from XML file.")
    

def checkImg(imgData):
    #print(str(imgData.text))
    header = str(base64.b64decode(imgData)[:5])
    #print("{} b'\\xff\\xd8\\xff\\xe0\\00'".format(header))
    if header == "b'\\xff\\xd8\\xff\\xe0\\x00'":
        header = "JPEG"
    elif header == "b'\\x89PNG\\r'":
        header = "PNG"
    elif header == "b'GIF89'":
        header = "GIF"
    
    return header

def checkConsecutive(group):
    return sorted(group) == list(range(min(group),max(group)+1))

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
    
    try:
        #path = os.path.dirname(xmlFile)
        #print("{} {}".format(path, xmlFile))
        et = parse(xmlFile)
    except FileNotFoundError:
        print("File error, {} was either not found or could not read it!".format(xmlFile))
        exit()

    newFile = xmlReport()
    newFile.processFlaws(et)
    newFile.Analyze()

    print("="*50+"\n")
   
    newFile.cruftRemoval(et.getroot())
    writeToXML(xmlFile, et)
    
if __name__ == "__main__":
    main()
