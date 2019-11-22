#!/usr/bin/env python3.8
from defusedxml.ElementTree import *
from xml.etree.ElementTree import register_namespace
import base64
import copy
import json
from lxml import etree
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
                    for data in screenshot.findall(".//{http://www.veracode.com/schema/import}data"):
                        mime = checkImg(data.text)
                        screenshot.attrib["format"] = mime
                        data.text = data.text.strip()
            
            flawProps["Flaw Appendix"]["Instance Count"] = instanceNum
            self.flaws["Flaw #"+str(count)] = copy.deepcopy(flawProps)
            

    def Analyze(self):
        names = ["Name", "CWE", "Count", "CAPEC", "CVSS", "Description",
                    "Remediation", "Remediation Effort", "Exploit Description",
                    "Severity Description", "Note", "Input Vector", "Location",
                    "Exploit Difficulty"]

        digits = re.compile("([\d]+)")
        repoSteps = re.compile("Reproduction Steps\\n([=]*\\n|)([a-zA-Z0-9.!@#$%\
                                ^&*()_+\-=~`{}[\]\|:;'\",<>/?\\n\s\\t]*)")
	
        req_resp = re.compile("(The[a-zA-Z\s]+:\\n[=]+\\n[a-zA-Z0-9\s\\n\\t~!@#$\
                               %^&*()_+`\-=[\]{}\\\|;':\",.<>/?]*)")

        for flaw in self.flaws:
            print("{}: {}".format(flaw, self.flaws[flaw]["Flaw Name"]))
            
            for name in names:
                value = self.flaws[flaw]["Flaw "+name]

                if value == None or value == "":
                    print("[*]\t Flaw {} is missing.".format(name))

                elif name == "CAPEC":
                    if not isEmpty(name,value) and value == "0":
                        print("[*]\t Flaw {} has a 0 value.".format(name)) 

                elif name == "Count":
                    if not isEmpty(name,value):
                        print("[*]\t Flaw Counts/Instance Count: ({}/{})"\
                                .format(self.flaws[flaw]["Flaw Count"],\
                                self.flaws[flaw]["Flaw Appendix"]["Instance Count"]))

                elif name == "CVSS":
                    if not isEmpty(name,value):
                        nums = re.compile("([\d\.]{3})")
                        cvssNum = nums.search(self.flaws[flaw]["Flaw Note"]).group()\
                                if self.flaws[flaw]["Flaw Note"] != None else "0.0"
                        if float(value) != float(cvssNum):
                            print("[*]\t Flaw CVSS score({}) doesnt match the Note score({})."\
                                    .format(value,cvssNum))

                elif name == "CWE":
                    isEmpty(name,value)

                elif name == "Description":
                    hasTemplate(name,value)
                    isEmpty(name,value)
                    isTooBig(name,value)
                
                elif name == "Exploit Description": 
                    hasTemplate(name,value)
                    isEmpty(name,value)
                    isTooBig(name,value)

                elif name == "Exploit Difficulty":
                    if not isEmpty(name,value) and value == "0":
                        print("[*]\t Flaw {} has a 0 value.".format(name))

                elif name == "Input Vector":
                    isEmpty(name,value)
                    
                elif name == "Location":
                    if not isEmpty(name,value) and len(value) > 255:
                        print("[*]\t Flaw Location size is too large. 255 is the max length.")
            
                elif name == "Note":
                    hasTemplate(name,value)
                    isEmpty(name,value)
                    isTooBig(name,value)

                elif name == "Remediation":
                    hasTemplate(name,value)
                    isEmpty(name,value)
                    isTooBig(name,value) 

                elif name == "Remediation Effort":
                    if not isEmpty(name,value) and value == "0":
                        print("[*]\t Flaw {} has a 0 value.".format(name)) 

                elif name == "Severity Description":
                    hasTemplate(name,value)
                    isEmpty(name,value)
                    isTooBig(name,value) 

            for num in range(int(self.flaws[flaw]["Flaw Appendix"]["Instance Count"])):
                instanceBlock = self.flaws[flaw]["Flaw Appendix"]["Instance #"+str(num+1)]
                
                req_match = req_resp.search(instanceBlock)
                if req_match:
                        #print(req_match.group())
                        instanceBlock = instanceBlock.replace(req_match.group(),"")
                        #print(instanceBlock)

                inst = repoSteps.search(instanceBlock)
                group = []

                if inst:
                    repoBlock = inst.group(2)
                    repoLines = repoBlock.splitlines()
                    
                    hasTemplate("Intance #{}".format(num+1),instanceBlock)
        
                    for line in repoLines:
                        for index in range(len(repoLines)):
                            if digits.search(line[:3]):
                                group.append(int(digits.search(line[:3]).group()))
                                break

                if len(group) > 1 and not checkConsecutive(group):
                    #print(group)
                    #print(repoLines)
                    print("[*]\t Instance #{} has misnumbered steps.".format(num+1))

            #if flaw == "Flaw #1":
            #    print(json.dumps(self.flaws[flaw],sort_keys=True,indent=4))
            #    break
            print()


    def cruftRemoval(self, root):
        codeStr = ".//{http://www.veracode.com/schema/import}code"
        chklstStr = ".//{http://www.veracode.com/schema/import}checklistflaws"
        chklst = root.find(chklstStr)
        
        if len(root.attrib) == 5:
            root.attrib.pop("assurance_level", None)
        
        if root.findall(chklstStr):
            root.remove(chklst)  

        #print("[*]\t Cruft Removed from XML file.")


# XSD validation, see: https://stackoverflow.com/a/37972081/11777580
def xsdValidate(xml, xsd):
    xmlschema_doc = etree.parse(xsd)
    xmlschema = etree.XMLSchema(xmlschema_doc)
    xml_doc = etree.parse(xml)

    prvError = ""
    
    try:
        xmlschema.assertValid(xml_doc)
        print("[*]\t XML validated against XSD!")
        return True
    except etree.DocumentInvalid as err:
        print("[*]\t Errors with the XML:")
        for err in xmlschema.error_log:
            if prvError != err.line:
                print("\t\t Line {}: {}".format(err.line, err.message))
            prvError = err.line
        print()
        return False


def hasTemplate(name, value):
    default = re.compile("{[a-zA-Z\_\-:]+}")
    if default.search(value):
        print("[*]\t Flaw {} has template content still in it.".format(name))


def isTooBig(name, value):
    if name == "Description":
        if len(value) > 4000:
            print("[*]\t Flaw {} is too big. 4000 is the max length.".format(name))
            return True
    elif name == "Note":
        if len(value) > 1024:
            print("[*]\t Flaw {} is too big. 1024 is the max length.".format(name))
            return True
    else:
        if len(value) > 2048:
            print("[*]\t Flaw {} is too big. 2048 is the max length.".format(name))
            return True
    return False


def isEmpty(name, value):
    if not value:
        print("[*]\t Flaw {} is empty".format(name))
        return True
    return False


def checkImg(imgData):
    header = str(base64.b64decode(imgData)[:5])
    
    if header == "b'\\xff\\xd8\\xff\\xe0\\x00'":
        header = "JPG"
    elif header == "b'\\x89PNG\\r'":
        header = "PNG"
    elif header == "b'GIF89'":
        header = "GIF"
    
    return header


def checkConsecutive(group):
    return sorted(group) == list(range(min(group),max(group)+1))


def writeToXML(xmlFile, et):
    newFile = "NEW_" + xmlFile
    with open(newFile, "wb") as f:
        xmlString = tostring(et.getroot(), encoding="utf-8", method="xml")
        f.write(xmlString)

    print("[*]\t Changes have been written to: {}\n".format(newFile))
    return newFile

def fileExists(fileName):
    if not os.path.exists(fileName):
        print("File error, {} was either not found or could not read it!".format(fileName))
        exit()

def main():
    if len(sys.argv) < 2:
        print("$ ./xmlparsing_test.py <file name>")
        sys.exit(1)
    else:
        xmlFile = sys.argv[1] 

    path_to_schema = "manualflawfeed.xsd"
    register_namespace("", "http://www.veracode.com/schema/import")
    
    fileExists(xmlFile)
    fileExists(path_to_schema)

    et = parse(xmlFile)

    newFile = xmlReport()
    newFile.processFlaws(et)
    newFile.Analyze()

    print("="*50+"\n")
   
    newFile.cruftRemoval(et.getroot())
    newXML = writeToXML(xmlFile, et)

    if not xsdValidate(newXML, path_to_schema):
        print("[*]\t XSD check failed, fixes to the XML may have been applied.\
		 Work off of {} and try again.".format(newXML))


if __name__ == "__main__":
    main()
