
import argparse
import re
import sys
import yaml
from common_lib import utils
import ast
import traceback
import inspect
import operator
from copy import deepcopy



###############################################################################
#                                                                             #
#                     Parser utils                                            #
#                                                                             # 
###############################################################################

###############################################################################
#
# Function: parseConfig
#
# Arguments: inputstring, inputgrammar
#
# inputstring : is in the form of concatenated strings of "-<key> <value>
#               Example is "-vrf_name default -hsrp_version 2" 
# inputgrammar: is a dictionary {'vrf_name': '-default x -type str', \
#                'hsrp_version' : '-type int -default 2'}
#
# Returns: Namespace of the form Namespace(vrf_name='default',hsrp_version=2)
#
##############################################################################

def parseConfig(input,grammar):
    # Initialize ArgumentParser for grammar
    caller=""
    if len(inspect.stack()) >= 3:
       if len(inspect.stack()[2]) >= 4:
           caller="{0} {1}".format(inspect.stack()[2][1],inspect.stack()[2][3])
      
    actualParser=argparse.ArgumentParser(prog=caller,description=caller)

    # Traverse each key in grammar
    for key in grammar.keys():

        # Set the Argparse arguments to Parse grammar key using Argparse
        grammarParser=argparse.ArgumentParser( prog="Grammar Parser",\
        description="Grammar Parser" )
        grammarParser.add_argument('-action',action='store',dest='action',\
        choices=['store'], default='store' )
        grammarParser.add_argument('-type',action='store',dest='type')
        grammarParser.add_argument('-default',action='store',dest='default')
        grammarParser.add_argument('-choices',action='store',dest='choices')
        grammarParser.add_argument('-required',action='store',dest='required')
        grammarParser.add_argument('-format',action='store',dest='format')
        grammarParser.add_argument('-minus',action='store',dest='minus')
        grammarParser.add_argument('-mandatoryargs',action='store',dest='mandatoryargs')
        grammarParser.add_argument('-dependency',action='store',dest='dependency')

        # Since grammar is specified of the form key instead of -key
        # Prepeand "-"
        option="-"+key

        if key == "mutualExclusive" or key == "mutualInclusive" or key == "oneMandatory" or key == "flags":
           continue

        # If no grammar is specified, then just add the argument to store 
        if grammar[key] == None:
                actualParser.add_argument(option,action='store',\
                    dest=key)
        else:
                # Parse the grammar for the given key 
                grammarkey=""
                previousattr=""
                previousisattr=False
                previouselement=""
                for element in grammar[key].split():
                    if element.startswith("-"):
                       previousattr=element
                       previousisattr=True
                       grammarkey=grammarkey+" " +element+" "
                    else:
                       if previousisattr:
                           grammarkey=grammarkey+element
                       else:
                           if previousattr == "-choices" and previousisattr:
                               grammarkey=grammarkey+element
                           elif previousattr == "-choices" and not previousisattr:
                               if previouselement.strip().endswith(","):
                                   grammarkey=grammarkey+element
                               else:
                                   grammarkey=grammarkey+"$SPACE$"+element
                           elif previousattr == "-default":
                               grammarkey=grammarkey+"$SPACE$"+element
                           else:
                               grammarkey=grammarkey+element+" "
                       previousisattr=False
                    previouselement=element
                if grammarkey != "":
                     grammar[key]=grammarkey

                grammarargs=grammarParser.parse_args(grammar[key].split())
                if grammarargs.default != None:
                    grammarargs.default=re.sub("\$SPACE\$"," ",grammarargs.default)

                if grammarargs.choices != None:
                    choices=[]
                    for elem in grammarargs.choices.split(","):
                        elem=elem.strip("[]")
                        elem=elem.strip('"')
                        elem=elem.strip("'")
                        choices.append(elem)
                    grammarargs.choices=[]
                    grammarargs.choices=choices

                kwargs={}
                kws=['choices','default','required']
                kwargs['dest']=key

                if grammarargs.type != None:
                    kwargs['type']=globals()['__builtins__'][grammarargs.type]
                
                for k in kws:
                    if getattr(grammarargs,k) != None:
                        kwargs[k]=getattr(grammarargs,k)

                actualParser.add_argument(option,**kwargs)

    cnt=0
    new_list=[]
    tmp=input.split()
    while cnt < len(tmp):
        val=tmp[cnt]
        t=re.match("-(\w+)",val)
        if t.group(1) in grammar.keys():        
            new_list.append(val)    
            new_list.append(tmp[cnt+1])
        cnt=cnt+2

    # Parse the given input against the given grammar
    actualargs=actualParser.parse_args(new_list)
 
    # return the namespace
    return actualargs

def returnParserFailure(returnType):

    emptyNamespace=argparse.Namespace()
    emptyNamespace.KEYS=[]
    emptyNamespace.VALIDARGS=False

    if returnType == "str":
        return ""
    elif returnType == "namespace":
        return emptyNamespace
    elif returnType == "dict":
        return {}

###############################################################################
#
# Function: argsToCommandOptions
#
# Arguments: inputargs, inputgrammar, log, returnType
#
# This procedure will in turn will call parseConfig, but parseConfig
# is best used for topology parsing & this is best used for variable
# argument parsing
#
# inputargs   : This is either tuple of string (When args is passed,\
#               it is usually tuple) 
#               Example is (-vlan 5', '-port Po21') or ('-vlan 5 -port Po21')
# inputgrammar: is a dictionary {'vrf_name': '-default x -type str', \
#               'hsrp_version' : '-type int -default 2'}
# log         : If some failure happens, logs will be printed to message
# returnType  : By default namespace, can be changed to str or dict
#
# Returns     : Returns based on returnType
#
# Unlike Argparse, in addition to attribute,values, there's one special 
# attribute added called 'KEYS' which is a list of all attributes so that
# it can be accessed like dict.keys(), namespace.KEYS
#
# If input grammar has -position defined and str return option is chosen
# then return string is appended according to the grammar specification
# If input grammar doesnt have -position defined, then str is returned as
# per the inputargs order (Originally Argparse sorts & looses order, wrapper
# handles it)
#
# When returnType is namespace, then namesppace.KEYS is ordered according
# to the grammar positions if specified, if not based on inputargs
##############################################################################

def argsToCommandOptions(argTuple,arggram,log,returnType="namespace",argexclude=[],argprepend="",argremovekeys=[]):

    arggrammar=deepcopy(arggram)

    positions={}
    argPosition=1
    argStr=""

    commandNamespace=argparse.Namespace()
    commandNamespace.VALIDARGS=True
    commandOptionsStr=""
    commandOptionsDict={}

    if type(argTuple) is not tuple and type(argTuple) is not str:
        return returnParserFailure(returnType)

    # This is to handle the scenario of argTuple being 
    # '(-vlan 5 -interface 6/47)' instead of ('-vlan 5', '-interface 6/47') 
    if len(argTuple) == 1 or re.search('str',str(type(argTuple))): 
         previousIsAttr=False
         ignoreKey=False
         if re.search('str',str(type(argTuple))):
             argTuple=re.sub("\n","$NEWLINE$",argTuple)
             tobeescapedlist=re.findall('\"[^\"]+\"',argTuple)
             for elem in tobeescapedlist:
                 searchlist=re.search(" \-",elem)
                 if not searchlist:
                     continue
                 substitutedelem=re.sub(" \-"," \\-",elem)
                 argTuple=re.sub(elem,substitutedelem,argTuple)
             arglist=argTuple.split()
         else:
             argTuple0=re.sub("\n","$NEWLINE$",argTuple[0])
             tobeescapedlist=re.findall('\"[^\"]+\"',argTuple0)
             for elem in tobeescapedlist:
                 searchlist=re.search(" \-",elem)
                 if not searchlist:
                     continue
                 substitutedelem=re.sub(" \-"," \\-",elem)
                 argTuple0=re.sub(elem,substitutedelem,argTuple0)
             arglist=argTuple0.split()
         for element in arglist:
             if element.startswith("-"):
                # Retain the input arg order
                positions[argPosition]=element[1:len(element)]
                argPosition=argPosition+1
                if 'flags' in arggrammar.keys() and 'ignore_unknown_key' in arggrammar['flags'] and element[1:len(element)] not in arggrammar.keys():
                    ignoreKey=True
                    continue
                # If two consecutive arguments are passed, then the 
                # first one is intended to be a flag 
                if previousIsAttr:
                    argStr = argStr + " FLAG " + element
                else:
                    argStr = argStr + " " + element
                previousIsAttr=True
                ignoreKey=False
             else:
                if ignoreKey:
                    continue
                if previousIsAttr:
                    argStr = argStr + " " + element
                    previousIsAttr=False
                else:
                    argStr = argStr + "$SPACE$" + element
         # This is to handle when last attribute is a flag
         if previousIsAttr and not ignoreKey:
            argStr = argStr + " FLAG"
         argTuple=argStr 
    # This is to handle the second input format
    elif "__iter__" in dir(argTuple):
        for i in range(len(argTuple)):
            if len(argTuple[i].split()) == 2:
                argStr=argStr + argTuple[i] + " "
            elif len(argTuple[i].split()) == 1:
                argStr=argStr + argTuple[i] + " FLAG" + " "
            elif len(argTuple[i].split()) > 2:
                tmpstr=argTuple[i]
                tobeescapedlist=re.findall('\"[^\"]+\"',tmpstr)
                for elem in tobeescapedlist:
                    searchlist=re.search(" \-",elem)
                    if not searchlist:
                        continue
                    substitutedelem=re.sub(" \-"," \\-",elem)
                    tmpstr=re.sub(elem,substitutedelem,tmpstr)
                argStr=argStr + tmpstr.split()[0] + " " + tmpstr.split()[1] 
                for elem in tmpstr.split()[2:len(tmpstr.split())]:
                     argStr=argStr+"$SPACE$"+elem
                argStr=argStr + " "
            positions[argPosition]=argTuple[i].split()[0][1:len(argTuple[i].split()[0])]
            argPosition = argPosition+1
        argTuple=argStr


    # Get the positions in the grammar specification
    tempPositions=re.findall("-position[ \t]*([0-9]+)",str(arggrammar),flags=re.I)
    defaultPosition=51
    arggrammarPositions={}
    arggrammarFormats={}
    arggrammarMandatory={}
    arggrammarDefaults={}
    arggrammarSubsets={}
    arggrammarMinus={}
    arggrammarType={}
    arggrammarBool=[]
    arggrammardependencies={}
    arggrammarpop={}
    ops={}
    ops['!='] = operator.ne
    ops['=='] = operator.eq
    ops['<='] = operator.le
    ops['>='] = operator.ge
    ops['<'] = operator.lt
    ops['>'] = operator.gt

    # Go through this only if grammar has position specified
    if len(tempPositions) > 0:
        for key in arggrammar.keys():
            if key == "mutualExclusive" or key == "mutualInclusive" or key == "oneMandatory":
                continue
            position=re.findall("-position ([0-9])+", arggrammar[key], flags=re.I)
            if len(position) == 0:
                # If no position for some arguments, then they need to be
                # ordered after positional arguments
                arggrammarPositions[defaultPosition] = key
                defaultPosition = defaultPosition + 1
            else:
                if len(position) > 1:
                    if log:
                       log.error("{0}".format(inspect.stack()))
                       log.error("-position  is specified multiple times for "+ arggrammar[key])
                    print("{0}".format(inspect.stack())) 
                    print("-position  is specified multiple times for "+ arggrammar[key])
                    return returnParserFailure(returnType)
                elif position[0] in arggrammarPositions.keys():
                    if log:
                        log.error("{0} ".format(inspect.stack()))
                        log.error("Same -position " + str(position[0]) + " is specified for "+ arggrammarPositions[position[0]] + " and " +  key)
                    print("{0}".format(inspect.stack())) 
                    print("Same -position " + str(position[0]) + " is specified for "+ arggrammarPositions[position[0]] + " and " +  key)
                    return returnParserFailure(returnType)
                else:
                    arggrammarPositions[position[0]] = key
                arggrammar[key]=re.sub("-position ([0-9])+", "", arggrammar[key])
        positions=arggrammarPositions

    for key in arggrammar.keys():
        if key == "mutualExclusive" or key == "mutualInclusive" or key == "oneMandatory" or not 'startswith' in dir(arggrammar[key]) :
            continue
        if "-format" in arggrammar[key].split():
            formatlist=re.search("-format\s+(.*)\s+\-",arggrammar[key])
            if not formatlist:
                formatlist=re.search("-format\s+(.*)",arggrammar[key])
            if formatlist:
                arggrammarFormats[key]=formatlist.group(1)
                arggrammar[key]=arggrammar[key].replace(arggrammarFormats[key],"")
                arggrammar[key]=arggrammar[key].replace('-format',"")
        if "-default" in arggrammar[key].split():
            arggrammarDefaults[key]=arggrammar[key].split()[arggrammar[key].split().index('-default')+1]                   
        if "-mandatoryargs" in arggrammar[key].split():
            arggrammarMandatory[key]=arggrammar[key].split()[arggrammar[key].split().index('-mandatoryargs')+1]
        if re.search("\-subset",arggrammar[key]):
            choicelist=re.findall("\-subset[ /t]+(.*)\s+\-",arggrammar[key])
            if not choicelist:
                choicelist=re.findall("\-subset[ /t]+(.*)",arggrammar[key])
            choices=utils.strtolist(choicelist[0])
            choices[len(choices)-1]=choices[len(choices)-1].strip('"]')
            choices[len(choices)-1]=choices[len(choices)-1].strip("'")
            arggrammarSubsets[key]=choices
            arggrammar[key]=arggrammar[key].replace("-subset "+choicelist[0],"")
        if re.search("-type[ \t]+str",arggrammar[key]):
            arggrammarType[key]='str'
        if re.search("-type[ \t]+dict",arggrammar[key]):
            arggrammarType[key]='dict'
            arggrammar[key]=re.sub("-type[ /t]+dict","-type str",arggrammar[key])
        if re.search("-type[ \t]+list",arggrammar[key]):
            arggrammarType[key]='list'
            arggrammar[key]=re.sub("-type[ /t]+list","-type str",arggrammar[key])
        if re.search("-type[ \t]+tuple",arggrammar[key]):
            arggrammarType[key]='tuple'
            arggrammar[key]=re.sub("-type[ /t]+tuple","-type str",arggrammar[key])
        if "-minus" in arggrammar[key].split():
            arggrammarMinus[key]=arggrammar[key].split()[arggrammar[key].split().index('-minus')+1]
        if re.search("-type\s+bool",arggrammar[key]): 
            arggrammarBool.append(key)
        if "-dependency" in arggrammar[key].split():
            dependencylist=re.search("-dependency\s+(.*)\s+\-",arggrammar[key])
            if not dependencylist:
                dependencylist=re.search("-dependency\s+(.*)",arggrammar[key])
            if dependencylist:
                arggrammardependencies[key]=dependencylist.group(1)
        if "-pop" in arggrammar[key].split():
            poplist=re.search("-pop\s+(\[.*\])",arggrammar[key])
            if poplist:
                arggrammarpop[key]=ast.literal_eval(poplist.group(1))
                arggrammar[key]=arggrammar[key].replace(poplist.group(1),"")
                arggrammar[key]=arggrammar[key].replace('-pop',"")
            else:
                print("{0} has -pop but couldn't extract pop value".format(key))
                if log:
                    log.error("{0} has -pop but couldn't extract pop value".format(key))
                    returnParserFailure(returnType)

    # In turn call, parseConfig
    try:
        argObj=parseConfig(argTuple,arggrammar)
    except:
        if log:
            log.error("{0} {1} {2} {3} ".format(sys.exc_info()[0],sys.exc_info()[1],traceback.extract_tb(sys.exc_info()[2]),inspect.stack()))
        print("{0} {1} {2} {3}".format(sys.exc_info()[0],sys.exc_info()[1],traceback.extract_tb(sys.exc_info()[2]),inspect.stack())) 
        return returnParserFailure(returnType)


    keys = []
    noneKeys = []
    defaultKeys = []

    for key in dir(argObj):
        # Dont bother processing built in attributes of name space
        if re.match('^_',key,flags=re.I):
            continue
        value = argObj.__getattribute__(key)
        newvalue = re.sub("\$SPACE\$"," ",str(value))
        newvalue = re.sub("\$NEWLINE\$","\r\n",newvalue)
        if newvalue.startswith("\-"):
            newvalue=newvalue[1:len(newvalue)]
        while newvalue.find(" \-") >= 0:
            newvalue=newvalue.replace(" \-"," -")
        if newvalue != str(value):
            value=newvalue
        if value == 'FLAG':
            if key in arggrammarBool:
                setattr(commandNamespace,key,True)
            else: 
                setattr(commandNamespace,key,"")
            keys.append(key)
        elif value != None:
            keys.append(key)
            setattr(commandNamespace,key,value)
        else:
             noneKeys.append(key)

    returnkeys=[]
    defaultkeys=[]
    positionkeys=sorted(positions.keys())
    #positionkeys.sort()
    for key in positionkeys:
        if positions[key] in keys:
           returnkeys.append(positions[key]) 
    for key in keys:
        if not key in returnkeys:
            returnkeys.append(key)
        if key in arggrammarDefaults.keys():
           if getattr(commandNamespace,key) == arggrammarDefaults[key] and not re.search("-"+key, argTuple):
               defaultkeys.append(key)

    for key in returnkeys:
        if key in arggrammarType.keys():
            if arggrammarType[key] == 'dict' or arggrammarType[key] == 'list' or arggrammarType[key] == 'tuple':
               setattr(commandNamespace,key,ast.literal_eval(getattr(commandNamespace,key)))
               if arggrammarType[key] == 'list' and not re.search('list',str(type(getattr(commandNamespace,key)))):
                   templist=[]
                   templist.append(getattr(commandNamespace,key))
                   setattr(commandNamespace,key,templist)
               if type(getattr(commandNamespace,key)) is not globals()['__builtins__'][arggrammarType[key]]: 
                    if log:
                        log.error("{0} ".format(inspect.stack()))
                        log.error("{0} type is {1} but actual is {2}".format(key,arggrammarType[key],type(getattr(commandNamespace,key))))
                    print("{0} ".format(inspect.stack()))
                    print("{0} type is {1} but actual is {2}".format(key,arggrammarType[key],type(getattr(commandNamespace,key))))

    if 'mutualExclusive' in arggrammar.keys():
        for ekeys in arggrammar['mutualExclusive']:
            mutualExclusiveFound = False
            if ekeys[len(ekeys)-1].startswith('-dependency'):
                dependentlist=ekeys[len(ekeys)-1].split()
                dependentlist=dependentlist[1:len(dependentlist)]
                (dependentkey,op,value)=dependentlist
                if dependentkey in returnkeys:
                    if op not in ops.keys():
                         if log:
                             log.error("supported operations are {0} but actual is".format(ops.keys(),op))
                             log.error("{0} ".format(inspect.stack()))
                         print("supported operations are {0} but actual is".format(ops.keys(),op))
                         print("{0}".format(inspect.stack()))
                         return returnParserFailure(returnType)
                    if not ops[op](getattr(commandNamespace,dependentkey),value):
                         continue
                    else:
                         if log:
                             log.info("dependency for mutualexclusive is met {1} {2} {3} but {1} is {4}".format(dependentkey,op,value,getattr(commandNamespace,dependentkey)))
                         print("dependency for mutualexclusive is met {1} {2} {3} but {1} is {4}".format(dependentkey,op,value,getattr(commandNamespace,dependentkey)))
                ekeys=ekeys[:len(ekeys)-1]
            for key in ekeys:
                if key in returnkeys and key not in defaultkeys:
                    if mutualExclusiveFound:
                        if log:
                            log.error("{0} ".format(inspect.stack()))
                            log.error("Return keys " + str(returnkeys) + " has mutual exclusive keys " + str(arggrammar['mutualExclusive']))
                        print("{0}".format(inspect.stack())) 
                        print("Return keys " + str(returnkeys) + " has mutual exclusive keys " + str(arggrammar['mutualExclusive']))
                        return returnParserFailure(returnType)
                    mutualExclusiveFound=True

    if 'mutualInclusive' in arggrammar.keys():
        for ikeys in arggrammar['mutualInclusive']:
            onefound=False
            allfound=True
            for key in ikeys:
                if key in returnkeys:
                    onefound=True
                else: 
                    allfound=False
            if onefound and not allfound:
                if log:
                    log.error("{0} ".format(inspect.stack()))
                    log.error("Return keys " + str(returnkeys) + " doesnt have all the mutual inclusive keys " + str(keys))
                print("{0}".format(inspect.stack())) 
                print("Return keys " + str(returnkeys) + " doesnt have all the mutual inclusive keys " + str(keys))
                return returnParserFailure(returnType)

    for key in arggrammarMinus.keys():
        if key not in arggrammarSubsets.keys() or arggrammarMinus[key] not in arggrammar.keys() or arggrammarMinus[key] \
            not in arggrammarSubsets.keys() or arggrammarMinus[key] in arggrammarMinus.keys() or \
            (key in arggrammarSubsets.keys() and arggrammarMinus[key] in arggrammarSubsets.keys() and \
            arggrammarSubsets[key] != arggrammarSubsets[arggrammarMinus[key]]):
            print("{0}".format(inspect.stack())) 
            if log:
                log.error("{0} ".format(inspect.stack()))
            if key not in arggrammarSubsets.keys():
               if log:
                   log.error("{0} has -minus but doesnt have -subset".format(key))
               print("{0} has -minus but doesnt have -subset".format(key))
            elif arggrammarMinus[key] not in arggrammar.keys():
               if log:
                   log.error("{0} has {1} as -minus but {1} doesnt exist in grammarspecification".format(key,arggrammarMinus[key]))
               print("{0} has {1} as -minus but {1} doesnt exist in grammarspecification".format(key,arggrammarMinus[key]))
            elif arggrammarMinus[key] not in arggrammarSubsets.keys():
               if log:
                   log.error("{0} has {1} as -minus but {1} doesnt have subset speficiation".format(key,arggrammarMinus[key]))
               print("{0} has {1} as -minus but {1} doesnt have subset speficiation".format(key,arggrammarMinus[key]))
            elif arggrammarMinus[key] in arggrammarMinus.keys():
               if log:
                   log.error("{0} has {1} as -minus and {1} also has {0} as -minus".format(key,arggrammarMinus[key]))
               print("{0} has {1} as -minus and {1} also has {0} as -minus".format(key,arggrammarMinus[key]))
            else:
               if log:
                   log.error("{0} has {1} as subset and {2} has {3} as subset. Both should have same susbet ".format(key,\
                       arggrammarSubsets[key],arggrammarMinus[key], arggrammarSubsets[arggrammarMinus[key]]))
               print("{0} has {1} as subset and {2} has {3} as subset. Both should have same susbet ".format(key,\
                   arggrammarSubsets[key],arggrammarMinus[key], arggrammarSubsets[arggrammarMinus[key]]))
            return returnParserFailure(returnType)

    for key in arggrammarSubsets.keys():
        if key in returnkeys:
          valuelist=getattr(commandNamespace,key)
          if type(valuelist) is not list:
              valuelist=utils.strtolist(valuelist)
          for elem in valuelist:
            if elem not in arggrammarSubsets[key]:
                if log:
                    log.error("{0} ".format(inspect.stack()))
                    log.error("Value for {0} is expected to be subset of {1} but actual is {2}".format(key,arggrammarSubsets[key],getattr(commandNamespace,key)))
                print("{0}".format(inspect.stack())) 
                print("Value for {0} is expected to be subset of {1} but actual is {2}".format(key,arggrammarSubsets[key],getattr(commandNamespace,key)))
                return returnParserFailure(returnType)
            if getattr(commandNamespace,key) == "all":
                templist=arggrammarSubsets[key]
                if 'none' in templist:
                    templist.pop(templist.index('none'))
                if 'all' in templist:
                    templist.pop(templist.index('all'))
                setattr(commandNamespace,key,utils.listtostr(templist))
        if key not in arggrammarMinus.keys() or arggrammarMinus[key] not in returnkeys:
            continue
        if key in returnkeys:
            finallist=utils.strtolist(getattr(commandNamespace,key))
            minusattrvalue = ""
        else:
            finallist=arggrammarSubsets[key]
            if 'none' in finallist:
                finallist.pop(finallist.index('none'))
            if 'all' in finallist:
                finallist.pop(finallist.index('all'))
            returnkeys.append(key)
            noneKeys.pop(noneKeys.index(key))
            if arggrammarMinus[key] in returnkeys: 
                minusattrvalue = getattr(commandNamespace,arggrammarMinus[key])
            else:
                minusattrvalue = ""
        if minusattrvalue == "none":
             for elem in arggrammarSubsets[arggrammarMinus[key]]:
                 if elem not in finallist and elem not in ['none','all']:
                     finallist.append(elem)
        elif minusattrvalue == "all":
             for elem in arggrammarSubsets[arggrammarMinus[key]]:
                 if elem in finallist:
                     finallist.pop(finallist.index(elem))
        elif minusattrvalue:
             for elem in utils.strtolist(minusattrvalue):
                 if elem in finallist:
                     finallist.pop(finallist.index(elem))        
        setattr(commandNamespace,key,utils.listtostr(finallist)) 

    for key in arggrammarFormats.keys():
        if key not in returnkeys:
            continue
        if key not in arggrammarType.keys() or arggrammarType[key] not in ['list','tuple']:
            matchList=re.search(arggrammarFormats[key],getattr(commandNamespace,key),flags=re.I)
            if not matchList or matchList.group(0) != getattr(commandNamespace,key): 
                if log:
                    log.error("{0} ".format(inspect.stack()))
                    log.error("Format for  " + key + " is " + arggrammarFormats[key] + " and actual is " +  getattr(commandNamespace,key))
                print("{0}".format(inspect.stack())) 
                print("Format for  " + key + " is " + arggrammarFormats[key] + " and actual is " +  getattr(commandNamespace,key))
                return returnParserFailure(returnType)
        else:
           valuelist=getattr(commandNamespace,key)
           for value in valuelist:
               matchlist=re.search(arggrammarFormats[key],value)
               if not matchlist or matchlist.group(0) != value:
                   if log:
                        log.error("{0} ".format(inspect.stack()))
                        log.error("Format for  " + key + " is " + arggrammarFormats[key] + " and actual is " +  value)
                   print("{0}".format(inspect.stack())) 
                   print("Format for  " + key + " is " + arggrammarFormats[key] + " and actual is " +  value)
                   return returnParserFailure(returnType)
                        

    for key in arggrammarMandatory.keys():
        if key not in returnkeys:
            continue
        allfound=True
        for mandatorykey in arggrammarMandatory[key].split(","):
            if not str(mandatorykey) in returnkeys:
                allfound=False 
        if not allfound:
            if log:
                log.error("{0} ".format(inspect.stack()))
                log.error("Return keys " + str(returnkeys) + " doesnt have all the dependent keys " + str(arggrammarMandatory[key]))
            print("{0}".format(inspect.stack())) 
            print("Return keys " + str(returnkeys) + " doesnt have all the dependent keys " + str(arggrammarMandatory[key]))
            return returnParserFailure(returnType)

    if 'oneMandatory' in arggrammar.keys():
        for keys in arggrammar['oneMandatory']:
            onefound=False
            for key in keys:
                if key in returnkeys:
                    onefound=True
        if not onefound:
            if log:
                log.error("{0} ".format(inspect.stack()))
                log.error("Return keys " + str(returnkeys) + " doesnt have atleast one of the mandatory keys " + str(arggrammar['oneMandatory']))
            print("{0}".format(inspect.stack())) 
            print("Return keys " + str(returnkeys) + " doesnt have atleast one of the mandatory keys " + str(arggrammar['oneMandatory']))
            return returnParserFailure(returnType)

    for key in arggrammarBool:
        if key in returnkeys:
            value = ""
            defaultvalue = "Notbool"
            if re.search("-"+key, argTuple):
                value=argTuple.split()[argTuple.split().index('-'+key)+1]
                if value == 'FLAG':
                    value = 'True'
                matchlist=re.search("\-default\s+([\S]+)",arggrammar[key])
                if matchlist:
                    defaultvalue=matchlist.group(1)
                if value == defaultvalue:
                    if key not in defaultkeys:
                        defaultkeys.append(key)
            else:
                matchlist=re.search("\-default\s+([\S]+)",arggrammar[key])
                if matchlist:
                            value=matchlist.group(1) 
                            #if key not in defaultkeys:
                            #    defaultkeys.append(key)
            if value == 'False':
                setattr(commandNamespace,key,False)
            elif value == 'True':
                continue
            else:
                if log:
                    log.error("{0} ".format(inspect.stack()))
                    log.error("{0} has type as bool but value is {1}".format(key,value))
                print("{0}".format(inspect.stack())) 
                print("{0} has type as bool but value is {1}".format(key,value))
                return returnParserFailure(returnType)

    for key in arggrammardependencies.keys():
        if key in returnkeys:
           dependentlist=utils.strtolistoftuple(arggrammardependencies[key])
           value=getattr(commandNamespace,key)
           for (dependentkey,op,value) in dependentlist:
               if dependentkey not in returnkeys:
                   continue
               if op not in ops.keys():
                   if log:
                      log.error("supported operations are {0} but actual is".format(ops.keys(),op))
                      log.error("{0} ".format(inspect.stack()))
                   print("supported operations are {0} but actual is".format(ops.keys(),op))
                   print("{0}".format(inspect.stack())) 
                   return returnParserFailure(returnType)
               if not ops[op](getattr(commandNamespace,dependentkey),value):
                   if log:
                       log.error("dependency for key {0} is {1} {2} {3} but {1} is {4}".format(key,dependentkey,op,value,getattr(commandNamespace,dependentkey)))
                       log.error("{0} ".format(inspect.stack()))
                   print("dependency for key {0} is {1} {2} {3} but {1} is {4}".format(key,dependentkey,op,value,getattr(commandNamespace,dependentkey)))
                   print("{0}".format(inspect.stack())) 
                   return returnParserFailure(returnType)

    for key in arggrammarpop.keys():
        if key not in returnkeys:
           continue

        if key not in arggrammarSubsets.keys() and (key not in arggrammarType.keys() or arggrammarType[key] != 'list'):
            if log: 
               log.error("-pop is applicable for -subset or -type list only whereas grammar for {0} is {1}".format(key,arggrammar[key]))
               log.error("{0} ".format(inspect.stack()))
            print("-pop is applicable for -subset or -type list only whereas grammar for {0} is {1}".format(key,arggrammar[key]))
            print("{0} ".format(inspect.stack()))
            return returnParserFailure(returnType)

        for constraint in arggrammarpop[key]:
            if len(constraint) < 2:
               if log:
                   log.error("pop should've atleast 2 elements but actual is {0}".format(constraint))
                   log.error("{0} ".format(inspect.stack()))
               print("pop should've atleast 2 elements but actual is {0}".format(constraint))
               print("{0} ".format(inspect.stack()))
               return returnParserFailure(returnType)

            mandatoryexists=True
            for elem in constraint[1]:
                if elem not in getattr(commandNamespace,key):
                   mandatoryexists=False

            valuelist=getattr(commandNamespace,key)
            converttostr=False
            if type(valuelist) is not list:
                valuelist=utils.strtolist(valuelist)
                convertostr=True
            finalvaluelist=valuelist[:]
            for element in valuelist:
                if element in constraint[0] and not mandatoryexists: 
                    if log:
                        log.warning("for {0} if {1} exists and {2} doesnt exist, pop {1}".format(key,element,constraint[1]))
                        log.warning("{0} ".format(inspect.stack()))
                    print("for {0} if {1} exists and {2} doesnt exist, pop {1}".format(key,element,constraint[1]))
                    print("{0} ".format(inspect.stack()))
                    finalvaluelist.pop(finalvaluelist.index(element))
            if converttostr:
                 finalvaluelist=str(finalvaluelist)       
            setattr(commandNamespace,key,finalvaluelist)
               

    if returnType == "str":
        # Order according to the positional specification
        for key in returnkeys:
            if key not in argexclude: 
                value = getattr(commandNamespace,key)
                if value == True and re.search("bool",str(type(value))):
                    if key not in argremovekeys:
                        commandOptionsStr = commandOptionsStr + argprepend + key + " " 
                else:
                    if key not in argremovekeys:
                        commandOptionsStr = commandOptionsStr + argprepend + key + " " + str(value) + " "
                    else:
                        commandOptionsStr = commandOptionsStr + str(value) + " "
        return commandOptionsStr
    elif returnType =="dict":
        for key in returnkeys:
            commandOptionsDict[key]=getattr(commandNamespace,key) 
        return commandOptionsDict
    elif returnType =="namespace":
        setattr(commandNamespace,"KEYS",returnkeys)
        setattr(commandNamespace,"DEFAULTKEYS",defaultkeys)
        for key in noneKeys:
            setattr(commandNamespace,key,None)
        return commandNamespace

# Usage: namespacetostr(ns)
# Usage: namespacetostr(ns,['x'])
# Usage: namespacetostr(ns,['x'],'-')
# Usage: namespacetostr(ns,['x','y'],'-',['y'])
def namespacetostr(ns,argexclude=[],argprepend="",argremovekeys=[]):

    returnstr=""
    for key in ns.KEYS:
        if key not in argexclude:
            value = getattr(ns,key)
            if value == True and re.search("bool",str(type(value))):
                if key not in argremovekeys:
                        returnstr = returnstr + argprepend + key + " "
            else:
                if key not in argremovekeys:
                    returnstr = returnstr + argprepend + key + " " + str(value) + " "
                else:
                    returnstr = returnstr + str(value) + " "

    return returnstr

def convertToTopologyFile(tbfilename,varfile,pretopofile,outputfile,log):

    # Read testbed.yml
    fp=open(tbfilename,"r")
    testbeddict=yaml.load(fp)
    fp.close()

    fp=open(tbfilename,"r")
    testbedbuffer=fp.read()
    fp.close()

    # Read pretopology.yml
    fp=open(pretopofile,"r")
    buffer=fp.read()
    fp.close()
 
    # Read variables.yml
    fp=open(varfile,"r")
    vardict=yaml.load(fp)
    fp.close()

    # Get grammar definitions for testbed.yml parsing
    fp=open("topology_grammar.yml","r")
    grammardict=yaml.load(fp)
    fp.close()

    # Testbed.yml has device definition
    if 'devices' in testbeddict.keys():
        for device in testbeddict['devices'].keys():
            # If console server is used, substitute with ip
            if 'params' in testbeddict['devices'][device].keys():
                consoleserverlist=re.findall("console[ \t]*([a-zA-Z0-9]+),",\
                    testbeddict['devices'][device]['params'],flags=re.I|re.M)
                for consoleserver in consoleserverlist:
                    if 'management' in testbeddict.keys() and 'consoleservers'\
                        in testbeddict['management'].keys() and consoleserver \
                        in testbeddict['management']['consoleservers'].keys() \
                        and 'ip' in testbeddict['management']['consoleservers'][consoleserver]:
                        testbeddict['devices'][device]['params']=\
                            re.sub(consoleserver,\
                            testbeddict['management']['consoleservers'][consoleserver]['ip'],\
                            testbeddict['devices'][device]['params'])
                    else:
                        print("management: consoleservers: " + consoleserver \
                            + ": ip : not found in" + str(testbeddict))
                        log.error("management: consoleservers: " + \
                            consoleserver + ": ip : not found in" + \
                            str(testbeddict))
                # Store parsed values in dict format 
                testbeddict['devices'][device]['paramdict']=\
                    argsToCommandOptions(testbeddict['devices'][device]['params'],\
                    grammardict['topomap_config']['device']['params'],log,"dict")
                    
            # Parse all th einterface specification and store as dict
            if 'interfaces' in testbeddict['devices'][device].keys():
                for interface in testbeddict['devices'][device]['interfaces']:
                    testbeddict['devices'][device]['interfaces'][interface]=\
                        argsToCommandOptions(testbeddict['devices'][device]['interfaces'][interface],\
                        grammardict['topomap_config']['device']['interface'],\
                        log,"dict")

    

    # Get all the variables to be substituted from the pretopology.yml
    topovarlist=utils.uniqueList(re.findall("<([0-9a-zA-Z\._]+)>",buffer,flags=0))

    for var in topovarlist:

        # For testbed substitutions, hierarchical names could be specififed
        varlist=var.split(".")

        if len(varlist) == 1:
            if 'variables' in vardict.keys() and varlist[0] in \
                vardict['variables'].keys():
                buffer=re.sub("<"+var+">",vardict['variables'][var],buffer) 
            else:
                print(varlist[0] + " Not found in " + str(vardict)) 
                log.error(varlist[0] + " Not found in " + str(vardict)) 
            continue

        # In pretopology.yml file interface names are always referred
        # with respect to logial node name, change it to real device name
        if 'devicemapping' in vardict.keys() and varlist[0] in \
           vardict['devicemapping'].keys():
           subtestbeddict=\
               testbeddict['devices'][vardict['devicemapping'][varlist[0]]] 
        elif varlist[0] in testbedict.keys():
           subtestbeddict=testbeddict[varlist[0]]
        else:
           print(varlist[0] + " Not found in " +  str(testbeddict))
           log.error(varlist[0] + " Not found in " + str(testbeddict))
           continue

        # Traverse the dict to find the right substitution to replace
        for key in varlist[1:]:
            if 'interfaces' in subtestbeddict.keys() and \
                key in subtestbeddict['interfaces'].keys():
                subtestbeddict=subtestbeddict['interfaces'][key]
            else:
                subtestbeddict=subtestbeddict[key]

        # node01.interface1.name  and node01.interface1 will still refer
        # physical interface for the sake of simplicity
        if 'keys' in dir(subtestbeddict) and 'name' in subtestbeddict.keys():
            subtestbeddict=subtestbeddict['name']
        
        buffer=re.sub("<"+var+">",subtestbeddict,buffer) 

    # Append management section to the final topology.yml
    if 'management' in testbeddict.keys():
        addtobuffer=""
        for line in testbedbuffer.split("\n"):
            if line.startswith("management:"):
                addtobuffer=line+"\n"
            elif re.match("^[ \t]+",line,flags=re.I) and len(addtobuffer):
                addtobuffer=addtobuffer+line+"\n"
            elif len(addtobuffer):
                break
        buffer=buffer+addtobuffer
                   
    fp=open(outputfile,"w")
    fp.write(buffer)
    fp.close()

# Quick test cases to be repeated for future library changes
#import yaml
#import parserutils_lib
#fp=open("topology.yml")
#configdict=yaml.load(fp)
#fp.close()
#fp=open("topology_grammar.yml")
#grammardict=yaml.load(fp)
#fp.close()
#vpc_node1_domain_configs=configdict['vpc_config_dict']['node01']['vpc_domain_configs']
#vpc_domain_grammar=grammardict['vpc_config']['node']['vpc_domain_config']
#vpc_node1_peer_configs_Po1=configdict['vpc_config_dict']['node01']['vpc_peer_configs']['port-channel1']
#vpc_peer_int_grammar=grammardict['vpc_config']['node']['vpc_peer_configs']['port-channel']
#hsrp_config=configdict['hsrp_config_dict']['node01']
#hsrp_config_grammar=grammardict['hsrp_config']['node']
#dm=parserutils_lib.parseConfig(vpc_node1_domain_configs,vpc_domain_grammar)
#peer_po=parserutils_lib.parseConfig(vpc_node1_peer_configs_Po1,vpc_peer_int_grammar)
#hsrp1=parserutils_lib.parseConfig(hsrp_config,hsrp_config_grammar)
#print dm
#print peer_po
#print hsrp1

#def getMacaddressTableDict1 (output, log, *args):
#    arggrammar={}
#   arggrammar['address']= '-position 6'
#    arggrammar['dynamic']= '-position 5'
#    arggrammar['interface']= '-position 4'
#    arggrammar['secure']= '-position 3'
#    arggrammar['static']= '-position 2'
#    arggrammar['vlan']= '-type int -position 1'
#
#    arggrammar['address']= ''
#    arggrammar['dynamic']= ''
#    arggrammar['interface']= ''
#    arggrammar['secure']= ''
#    arggrammar['static']= ''
#    arggrammar['vlan']= '-type int'
#
#    command = "show mac address-table " + parserutils_lib.argsToCommandOptions(args,arggrammar,"x","str")
#    print command
#    command = parserutils_lib.argsToCommandOptions(args,arggrammar,"x","dict")
#    print command
#    command = parserutils_lib.argsToCommandOptions(args,arggrammar,"x","namespace")
#    print command
#getMacaddressTableDict1("test", "x")
#getMacaddressTableDict1("test", "x", "-interface ethernet6/47")
#getMacaddressTableDict1("test", "x",'-dynamic','-secure','-interface 6/47')
#getMacaddressTableDict1("test", "x", "-interface 6/47","-dynamic")
#getMacaddressTableDict1("test", "x", "-dynamic", "-interface 6/47")
#getMacaddressTableDict1("test", "x", "-vlan 5", "-interface 6/47")
#getMacaddressTableDict1("test", "x", "-vlan 5")
#getMacaddressTableDict1("test", "x", "-interface ethernet6/47")
#getMacaddressTableDict1("test", "x",'-dynamic -interface 6/47 -secure -vlan 5')
#getMacaddressTableDict1("test", "x",'-dynamic')
#getMacaddressTableDict1("test", "x", "-interface 6/47 -dynamic")
#getMacaddressTableDict1("test", "x", "-dynamic -interface 6/47")
#getMacaddressTableDict1("test", "x", "-vlan 5 -interface 6/47")
#getMacaddressTableDict1("test", "x", "-vlan 5")
