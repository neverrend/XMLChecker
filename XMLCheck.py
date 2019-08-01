#!/usr/bin/env python3 

## TODO: Put this all in a JSON object and simplify the loop.

import os
import re
import sys

def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)
    
    if os.path.isfile(sys.argv[1]) == True:
        fileName    = sys.argv[1]
    else:
        print("\nThe file supplied is not valid. Try again")
        sys.exit(1)

    if sys.platform == "win32":
        backslash   = "\\"
    else:
        backslash   = "/"   

    try:
        fd          = open(fileName, "r")
    except FileNotFoundError as fileErr:
        print("Error opening file:\n{}".format(fileErr))

    data            = fd.read()
    lines           = data.split("\n")
    
    # Compiled regexs to check for XSD junk first
    XSDCheck1       = re.compile("assurance_level=\"-1\"(?=[>])") # assurance_level="-1"
    XSDCheck2       = re.compile("<([/]|)checklistflaws>") # <checklistflaws></checklistflaws>
    XSDCheck3_1     = re.compile("(?:^[\s]+<location>)(.*)(?:<\\/location>$)") # Location character # checker
    XSDCheck3       = re.compile("(?:[\s]+<location>)") # Location character # checker
    XSDCheck4       = re.compile("<\/location>") # End of location checker
    
    flawCodeBlocks  = re.compile("(?:<code>)(.*)(?:<\\/code>)") # Code blocks
    flawCodeBlock   = re.compile("<code>(?!<\\\\code>)") # Code block
    flawCount       = re.compile("count=\"(\d)\"") # Instance Count
    flawDesc        = re.compile("(?:<description>)(.*)(?:<\\/description>)") # flaw description
    flawExploitDesc = re.compile("(?:<exploit_desc>)(.*)(?:<\\/exploit_desc>)") # flaw exploit description
    flawExploitDiff = re.compile("(?:<exploit_difficulty>)(.*)(?:<\\/exploit_difficulty>)") # Exploit difficulty
    flawInputVec    = re.compile("(?:<input_vector>)(.*)(?:<\\/input_vector>)") # Input vector
    flawName        = re.compile("(?:<name>)(.*)(?:<\\/name>)") # flaw names
    flawNote        = re.compile("(?:<note>)(.*)(?:<\\/note>)") # CVSS Score
    flawRemdiDesc   = re.compile("(?:<remediation_desc>)(.*)(?:<\\/remediation_desc>)") # flaw remediation description
    flawRemdiScore  = re.compile("(?:<remediationeffort>)(.*)(?:<\\/remediationeffort>)") # flaw remediation score
    flawSevDesc     = re.compile("(?:<severity_desc>)(.*)(?:<\\/severity_desc>)") # flaw Severity Description
    endOfFlaw       = re.compile("<\\/flaw>") # End of a flaw

    print('''
        ** * * * * * * * * * * * * * * * * * * * **
        **      *0*      *8*                     **
        **     \|/________\|/___________         **   
        **     ALWAYS CHECK THE NEW FILE         **
        **      THAT IS GENERATED IN MFFC        **
        **       I AM NOT INFALLABLE ;D          **
        **                                       **
        ** * * * * * * * * * * * * * * * * * * * ** 
    ''')
    
    codeCount       = 0
    count           = 0
    lineNum         = 0
    name            = ""
    rebuilt         = ""

    for x in lines:
        
        line = "" 
        
        if flawName.search(x):
            name = flawName.search(x)
            name = name.group(1)
            if len(name) == 0:
                print("Flaw name is missing on line # {}".format(lineNum+1))
                name = "<!MISSING!>"
            print("Flaw: {}".format(name))
        
        if flawCount.search(x):
            count = flawCount.search(x).group(1)

        a = XSDCheck1.search(x)
        if a:
            x = x.replace(a.group(), "")
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
                end = XSDCheck4.search(lines[lineNum])
                lineNum += 1

                if end:
                    line = len(list(line))
                    if line > 255:
                        print("- has to large of a location field. Remove some sites")
                    lineNum = orgLine
                    break

        d = XSDCheck3_1.search(x, re.MULTILINE)
        if d:
            print("- is missing locations")
    
        e = flawDesc.search(x)
        if e and len(e.group()) > 1 and len(e.group(1)) == 0:
            print("- is missing a description")

        f = flawRemdiScore.search(x)
        if f and len(f.group()) > 1 and f.group(1) == "0":
            print("- is missing a Remediation Score")

        g = flawRemdiDesc.search(x)
        if g and len(g.group()) > 1 and len(g.group(1)) == 0:
            print("- is missing a Remediation Description")

        h = flawExploitDesc.search(x)
        if h and len(h.group()) > 1 and len(h.group(1)) == 0:
            print("- is missing a Exploit description")

        i = flawSevDesc.search(x)
        if i and len(i.group()) > 1 and len(i.group(1)) == 0:
            print("- is missing a Severity description")

        j = flawNote.search(x)
        if j and len(j.group()) > 1 and len(j.group(1)) == 0:
            print("- is missing a CVSS score")

        k = flawInputVec.search(x)
        if k and len(k.group()) > 1 and len(k.group(1)) == 0:
            print("- is missing a Input Vector")

        l = flawExploitDiff.search(x)
        if l and len(l.group()) > 1 and l.group(1) == "0":
            print("- is missing Exploit Difficulty")

        m = flawCodeBlocks.search(x)
        if m:
            x = x.replace(m.group(), "")
            print("- had empty code blocks that were removed.")

        if flawCodeBlock.search(x):
            codeCount += 1
       
        if endOfFlaw.search(x): 
            if count != codeCount:
                print("- has a count of \"{}\" and \"{}\" many instances\n"
                        .format(count, codeCount))
            codeCount = 0

        rebuilt = rebuilt + x + "\n" 
        lineNum += 1

    
    newfilename = fileName.split(backslash)

    if sys.platform == "linux":
        newfilename = "." + backslash.join(newfilename[0:-1]) + (backslash + "new") + newfilename[-1]
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

