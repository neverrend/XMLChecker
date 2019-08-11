from defusedxml.ElementTree import *

#fd = open("xml.xml", "r")
#data = fd.read()

et = parse("xml.xml")
root = et.getroot()
attribs = ["cwe_id", "cvss", "capec_id", "count"]
flawParts = ["name","description", "remediationeffort",
             "remediation_desc", "exploit_desc", "severity_desc",
             "note", "input_vector", "location", "exploit_difficulty",
             "appendix/"]
count = 0 

for flaw in root.iter("{http://www.veracode.com/schema/import}flaw"):
    #if flaw.find
    #print("Flaw Name: {}"
    #        .format(flaw
    #            .find("{http://www.veracode.com/schema/import}name").text))
    for x in attribs:
        if flaw.attrib[x] == None:
            print("\t- {} is missing.".format(x))
        else:    
            print("Flaw Attribute {}: {}".format(x, flaw.attrib[x]))
    for x in flawParts:
        count = count + 1
        head = ".//{http://www.veracode.com/schema/import}"
        if x == "appendix/": x = "description"
        head = head + x
        if flaw.find(head).text == None:
            if x == "name":
                print("\t- Flaw #{} is missing a name".format(count))
            else:
                print("\t- {} is missing".format(x))
        else:
            print("Flaw Part {}:\n\t- {}".format(x, flaw.find(head).text))
    print()
    break
