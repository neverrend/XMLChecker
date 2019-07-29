#!/usr/bin/env python3 

import os
import re
import sys

def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)
    
    if os.path.isfile(sys.argv[1]) == True:
        fileName = sys.argv[1]
   
    if sys.platform == "win32":
        backslash = "\\"
    else:
        backslash = "/"

    #print("File name: {}".format(fileName))    

    fd = open(fileName, "r")
    data = fd.read()
    lines = data.split("\n")
    
    # Compiled regexs to check for XSD junk first
    XSDCheck1 = re.compile("assurance_level=\"-1\"(?=[>])") # assurance_level="-1"
    XSDCheck2 = re.compile("<([/]|)checklistflaws>") # <checklistflaws></checklistflaws>
    XSDCheck3_1 = re.compile("(?:^[\s]+<location>)(.*)(?:<\\/location>$)") # Location character # checker
    XSDCheck3 = re.compile("(?:[\s]+<location>)") # Location character # checker
    XSDCheck4 = re.compile("<\/location>") # End of location checker
    
    flawName = re.compile("(?:<name>)(.*)(?:<\\/name>)") # flaw names
    flawDesc = re.compile("(?:<description>)(.*)(?:<\\/description>)") # flaw description
    flawRemdiScore = re.compile("(?:<remediationeffort>)(.*)(?:<\\/remediationeffort>)") # flaw remediation score
    flawRemdiDesc = re.compile("(?:<remediation_desc>)(.*)(?:<\\/remediation_desc>)") # flaw remediation description
    flawExploitDesc = re.compile("(?:<exploit_desc>)(.*)(?:<\\/exploit_desc>)") # flaw exploit description
    flawSevDesc = re.compile("(?:<severity_desc>)(.*)(?:<\\/severity_desc>)") # flaw Severity Description
    flawNote = re.compile("(?:<note>)(.*)(?:<\\/note>)") # CVSS Score
    flawInputVec = re.compile("(?:<input_vector>)(.*)(?:<\\/input_vector>)") # Input vector
    flawExploitDiff = re.compile("(?:<exploit_difficulty>)(.*)(?:<\\/exploit_difficulty>)") # Exploit difficulty
    flawCodeBlocks = re.compile("(?:<code>)(.*)(?:<\\/code>)") # Code blocks

    print("searching")
    lineNum = 0
    name = ""
    rebuilt = ""
    for x in lines:
        line = "" 
        if flawName.search(x):
            name = flawName.search(x)
            name = name.group(1)
            if len(name) == 0:
                print("Flaw name is missing on line # {}".format(lineNum+1))

        #print(name)
        a = XSDCheck1.search(x)
        if a:
            x = x.replace(a.group(), "")
            #print(x)
            print("assurance_level found and deleted!")
        
        b = XSDCheck2.search(x)
        if b:
            x = x.replace(b.group(), "")
            print("<checklistflaws> found and deleted!")

        
        c = XSDCheck3.search(x)
        if c:
            orgLine = lineNum
            while range(len(lines[lineNum])):
                line = line + lines[lineNum]
                #print(line)
                end = XSDCheck4.search(lines[lineNum])
                lineNum += 1
                if end:
                    line = len(list(line))
                    if line > 255:
                        print("Flaw: {} has to large of a location field. Remove some sites".format(name))
                    lineNum = orgLine
                    break
        rebuilt = rebuilt + x 
        lineNum += 1

        d = XSDCheck3_1.search(x)
        if d:
            print("Flaw: {} is missing locations!".format(name))
    
        e = flawDesc.search(x)
        if e:
            if len(e.group()) > 1:
                if len(e.group(1)) == 0:
                    print("Flaw: {} is missing a description".format(name))

        f = flawRemdiScore.search(x)
        if f:
            if len(f.group()) > 1:
                if f.group(1) == "0":
                    print("Flaw: {} is missing a Remediation Score".format(name))

        g = flawRemdiDesc.search(x)
        if g:
            if len(g.group()) > 1:
                if len(g.group(1)) == 0:
                    print("Flaw: {} is missing a Remediation Description".format(name))

        h = flawExploitDesc.search(x)
        if h:
            if len(h.group()) > 1:
                if len(h.group(1)) == 0:
                    print("Flaw: {} is missing a Exploit description".format(name))

        i = flawSevDesc.search(x)
        if i:
            if len(i.group()) > 1:
                if len(i.group(1)) == 0:
                    print("Flaw: {} is missing a Severity description".format(name))

        j = flawNote.search(x)
        if j:
            if len(j.group()) > 1:
                if len(j.group(1)) == 0:
                    print("Flaw: {} is missing a CVSS score".format(name))

        k = flawInputVec.search(x)
        if k:
            if len(k.group()) > 1:
                if len(k.group(1)) == 0:
                    print("Flaw: {} is missing a Input Vector".format(name))

        l = flawExploitDiff.search(x)
        if l:
            if len(l.group()) > 1:
                if l.group(1) == "0":
                    print("Flaw: {} is missing Exploit Difficulty".format(name))

        m = flawCodeBlocks.search(x)
        if m:
            x = x.replace(m.group(), "")
            print("Flaw: {} had empty code blocks that were removed.".format(name))

    newfilename = fileName.split(backslash)

    if sys.platform == "linux":
        newfilename = backslash.join(newfilename[0:-1]) + (backslash + "new") + newfilename[-1]
    else:    
        newfilename = backslash.join(newfilename[0:-1]) + "new" + newfilename[-1]
    
    fd1 = open(newfilename, "w")
    fd1.write(rebuilt)

    fd.close()
    fd1.close()


def usage():
    print("$ ./XMLChecker.py <XMLfilename>")
    

if __name__ == "__main__":
    main()

