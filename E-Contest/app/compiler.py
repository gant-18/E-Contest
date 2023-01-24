# !/usr/bin/env python3
import random
import sys
MAX_SIZE = 5e6
MAX_CELLS  = 65536
MAX_VAL = 255
MIN_VAL = 0

def interpret(program,inputPath,outputPath,Q) :
    global MAX_CELLS, MAX_VAL, MIN_VAL, MAX_SIZE
    global lineno, ptr, data, brackets, inp_buff, out_buff, inp_ind
    out_buff = ''
    f1 = open("/Users/ganesht/PycharmProjects/E-Contest/app/check.txt", 'w')
    strlen = len(program)
    if (strlen > MAX_SIZE) :
        Q.put("MEMORY LIMIT EXCEEDED")
        return

    with open(inputPath, 'r') as f:
        inp_buff2 = f.readlines()
    inp_buff = inp_buff2
    inplen = len(inp_buff)

    rules = {}
    state = ""
    lines = program.split("\n")
    # If we are adding rules or adding initial state

    adding_rules = True
    for line in lines:
        line.strip("\n")
        if adding_rules:
            if "::=" in line:
                if line.replace(" ", "").replace("\t", "").replace("\n", "") == "::=":
                    adding_rules = False
                else:
                    # Add new rule
                    lh = line[0:line.find("::=")]
                    lh.strip("\n")
                    rh = line[line.find("::=") + 3::]
                    rh.strip("\n")
                    if lh not in rules:
                        rules[lh] = [rh]
                    else:
                        rules[lh].append(rh)
    #if not(adding_rules):
    if lines[-1] != "":
        state += lines[-1]
    state.strip('/n')
    f1.write(state)
    for r in rules:
        if r == "":
            del rules[r]
            break

    for r in rules:
        f1.write(r+"%")
        for k in rules[r]:
            f1.write(k)

    while True:
        f1.write(state)
        if rules is None or state is None or state == '':
            break

        # First select which rules we can use
        rule_keys = []
        for r in rules:
            if r in state:
                rule_keys.append(r)
        if len(rule_keys) == 0:
            break

        # Pick a random rule
        rkey = random.choice(rule_keys).strip("\n")
        rval = random.choice(rules[rkey]).strip("\n")
        rval2 = ""
        for r in rval:
            if ord(r)<128 and ord(r)>31:
                rval2 += r
        rval = rval2
        rkey2 = ""
        for r in rkey:
            if ord(r) < 128 and ord(r) > 31:
                rkey2 += r
        rkey = rkey2
        # rkey = rule_keys[0]
        # rval = rules[rkey][0]
        # Get random location
        locations = set([])
        for i in range(len(state)):
            loc = state[i::].find(rkey)+i
            if loc-i != -1:
                locations.add(loc)
        loc = random.choice(list(locations))

        # And replace
        # If it begins with a tilde, though, just output
        if len(rval)>0 and rval[0] == "~":
            out_buff += (rval[1::])
            #sys.stdout.flush()
            rval = ""
        elif rval == ":::":
        # ":::" replace with user input
            while(inp_buff[0]=="\n"):
                inp_buff.pop(0)
            f1.write("input")
            rval = inp_buff[0].strip("\n")
            inp_buff.pop(0)

        state = state[0:loc]+rval+state[loc+len(rkey)::]
        state2 = ""
        for r in state:
            if ord(r)<128 and ord(r)>31:
                state2 += r
        state = state2
    if out_buff == '':
        Q.put("SYNTAX ERROR: No output obtained")

    with open(outputPath,'w') as f:
        f.write(out_buff)
    f1.close()
    Q.put("ANSWER WRITTEN")
    return