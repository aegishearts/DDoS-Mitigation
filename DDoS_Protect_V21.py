#!/usr/bin/python3
import sys, os, time, pexpect, getpass, re, pprint
from multiprocessing import Process, Queue
from tkinter import *
from tkinter import ttk
from tkinter import font
from netaddr import *
from difflib import *

Mx = 85
My = 50

################################################################
### Backend Definitions
################################################################
BdrTerm = re.compile(r'BDR:')
IpHostTerm = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
IpAddTerm = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}')
PrefixCheckTerm = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$')
SecPrefixTerm = re.compile('set policy-options prefix-list pl-SEC')
BlackTerm = re.compile(r'community 36408:666')
OtpTerm = re.compile(r'[0-9]{6}')
S = None
ScriptError = None
Qerror = None
InCon = None
TgtPrefixList = ''
AsnIsp = {'XXXXX':'XXXXX'}                          # {'AS number','ISP name'}
RtrList = ['XXXXX',['XXXXX','XXXXX']]               # ['DC name', ['router hostname','router hostname']]

##################################################################
### Backend Functions
##################################################################
def DisplayText(VAR, VAR2, RTR, CQ):
    OutputFile = open(RTR + '.txt', 'a')
    bZ = (VAR + VAR2)
    Z = bytes.decode(bZ)
    A = Z.splitlines()
    E = -1
    for i in A:
        E = E + 1
        print(A[E])
        OutputFile.write(A[E] + '\n')
        #CQ.put(A[E])
    OutputFile.close()

### Backend Function
def GetRoutes(data, CQ, RouterIP, GL, OTP, S):
    ScriptError = ''
    BdrList = []
    IspIpAsnList = []
    RawPrefixList = []
    PrefixList = []
    try:
        if not S: 
            S = pexpect.spawn('ssh -o StrictHostKeyChecking=no -l ' + UserVar.get() + ' -i ' + GuiKeyFile.get() + ' -p 2113 ' + KssServer.get())

            S.expect('Password:')
            DisplayText(S.before, S.after, RouterIP, CQ)
            
            S.sendline(PassVar.get())
            DisplayText(S.before, S.after, RouterIP, CQ)
           
            S.expect('Verification code:', timeout=2) 
            S.sendline(OTP)
            S.expect('\[ssh\]:\$', timeout=2)
            DisplayText(S.before, S.after, RouterIP, CQ)

            S.sendline('ssh ' + RouterIP +'.net.cdngp.net ' + UserVar.get())
            try:
                S.expect('Password:', timeout=2)
                DisplayText(S.before, S.after, RouterIP, CQ)
                S.sendline(PassVar.get())
            except:
                pass
            S.expect('word:')
            DisplayText(S.before, S.after, RouterIP, CQ)
            S.sendline(PassVar.get())
            S.expect(RouterIP + '>')
            DisplayText(S.before, S.after, RouterIP, CQ)

        S.sendline('show configuration | display set | no-more')
        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)
        DeviceConfig = S.before
        DeviceConfig = bytes.decode(DeviceConfig)
        DeviceConfigList = DeviceConfig.splitlines()
        S.sendline('show interface descriptions | grep BDR')

        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)
        RawBdrList = (bytes.decode(S.before)).splitlines()

        E = -1
        for i in RawBdrList:
            E = E + 1
            match = BdrTerm.search(RawBdrList[E])
            if match:
                BdrList.append(RawBdrList[E])

        E = -1
        for i in BdrList:
            E = E + 1
            Tango = BdrList[E].split(':')
            tempList = []
            tempList.append(Tango[5])
            tempList.append(Tango[4])
            if tempList not in IspIpAsnList:
                IspIpAsnList.append(tempList)
        E = -1
        for i in IspIpAsnList:
            E = E + 1
            S.sendline('show route advertising-protocol bgp ' + IspIpAsnList[E][0] + ' | no-more')
            S.expect('\{master\}')
            DisplayText(S.before, S.after, RouterIP, CQ)
            tempList = (bytes.decode(S.before)).splitlines()
            RawPrefixList.append(tempList)
        E = -1
        for i in RawPrefixList:
            E = E + 1
            F = -1
            for j in RawPrefixList[E]:
                F = F + 1
                Alpha = IpAddTerm.search(RawPrefixList[E][F])
                if Alpha:
                    Cand = Alpha.group()
                    G = -1
                    Absent = 1
                    for k in PrefixList:
                        G = G + 1
                        if Cand in PrefixList[G]:
                            Absent = 0
                            PrefixList[G].append(AsnIsp[IspIpAsnList[E][1]])
                    if Absent == 1:
                        ParseList = [Cand, AsnIsp[IspIpAsnList[E][1]]]
                        PrefixList.append(ParseList)
        
        SecPrefixList = []
        for i in DeviceConfigList:
            Match = SecPrefixTerm.search(i)
            if Match:
                SecPrefixList.append(i.split())
        BlackRoutes = []
        for i in DeviceConfigList:
            M = BlackTerm.search(i)
            if M:
                BlackRoutes.append(i)
        BdrAclList = []
        for i in DeviceConfigList:
            if 'set firewall family inet filter acl-BDR-IN' in i:
                BdrAclList.append(i)
        AclSecList = []
        for i in BdrAclList:
            if 'term SEC from destination-address' in i:
                AclSecList.append(i.split())
             
        if (GL == '1') or (GL == 'SecondPass'):
            try:
                for n in range(2):
                    S.sendline('exit')
                    S.expect('#|>|\$')
                    DisplayText(S.before, S.after, RouterIP, CQ)
                    time.sleep(1)
            except:
                pass
            S.close()
            S = None
        ReturnData = (PrefixList, SecPrefixList, BlackRoutes, AclSecList, ScriptError)
        if GL == '1':
            #CQ.put('END_OF_SSH_SESSION')
            data.put(ReturnData)
        if GL == 'FirstPass':
            return(S, IspIpAsnList, DeviceConfigList, BdrAclList, AclSecList)
        if GL == 'SecondPass':
            return(PrefixList, SecPrefixList, BlackRoutes, AclSecList, ScriptError)
    except:
        if GL == '1':
            ScriptError = str(sys.exc_info())
            S.close()
            print(ScriptError)
            ReturnData = ('', '', '', '', ScriptError)
            #CQ.put('END_OF_SSH_SESSION')
            data.put(ReturnData)
        else:
            S.close()

### Backend Function
def StopAnnConfig(Target, ExportList, FirstTerms, S, RouterIP, CQ):
    if Target == 'Mega':
        for i in StopAnnList:
            S.sendline("set policy-options prefix-list pl-SEC " + i)
            S.expect('\{master\}')
            DisplayText(S.before, S.after, RouterIP, CQ)
    else:
        S.sendline("set policy-options prefix-list pl-SEC " + Target)
        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)
    E = -1
    for i in ExportList:
        E = E + 1
        S.sendline('set policy-options policy-statement ' + ExportList[E][6] + ' term SEC-BLOCK from prefix-list pl-SEC')
        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)

        S.sendline('set policy-options policy-statement ' + ExportList[E][6] + ' term SEC-BLOCK then reject')
        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)

        if FirstTerms[E][5] != 'SEC-BLOCK':
            S.sendline('insert policy-options policy-statement ' + ExportList[E][6] + ' term SEC-BLOCK before term ' + FirstTerms[E][5])
            S.expect('\{master\}')
            DisplayText(S.before, S.after, RouterIP, CQ)

### Backend Function
def StartAnnConfig(Target, S, RouterIP, CQ):
    if Target == 'Mega':
        for i in StartAnnList:
            S.sendline("delete policy-options prefix-list pl-SEC " + i)
            S.expect('\{master\}')
            DisplayText(S.before, S.after, RouterIP, CQ)
    else:
        S.sendline("delete policy-options prefix-list pl-SEC " + Target)
        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)

### Backend Function
def AdBlackTriggerConfig(Target, S, RouterIP, CQ):
    if Target == 'Mega':
        for i in TgtPrefixList:
            S.sendline('set routing-options static route ' + i + ' reject community 36408:666')
            S.expect('\{master\}')
            DisplayText(S.before, S.after, RouterIP, CQ)
    else:
        S.sendline('set routing-options static route ' + Target + ' reject community 36408:666')
        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)

### Backend Function
def RmBlackTriggerConfig(Target, S, RouterIP, CQ):
    S.sendline('delete routing-options static route ' + Target)
    S.expect('\{master\}')
    DisplayText(S.before, S.after, RouterIP, CQ)

def AddLocalFilter(Target, BdrAclList, S, RouterIP, CQ):
    if Target == 'Mega':
        for i in TgtPrefixList:
            S.sendline('set firewall family inet filter acl-BDR-IN term SEC from destination-address ' + i)
            S.expect('\{master\}')
            DisplayText(S.before, S.after, RouterIP, CQ)
    else:
        S.sendline('set firewall family inet filter acl-BDR-IN term SEC from destination-address ' + Target)
        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)
    S.sendline('set firewall family inet filter acl-BDR-IN term SEC then routing-instance MFI')
    S.expect('\{master\}')
    DisplayText(S.before, S.after, RouterIP, CQ)
    ### For testing!!!
    S.sendline('deactivate firewall family inet filter acl-BDR-IN term SEC')
    S.expect('\{master\}')
    DisplayText(S.before, S.after, RouterIP, CQ)

    if (BdrAclList[0].split())[7] != 'SEC':
        S.sendline('insert firewall family inet filter acl-BDR-IN term SEC before term ' + (BdrAclList[0].split())[7])
        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)

def RmLocalFilter(Target, AclSecList, S, RouterIP, CQ):
    if (len(AclSecList) == 1) or (len(AclSecList) == len(TgtPrefixList)):
        S.sendline('delete firewall family inet filter acl-BDR-IN term SEC')
        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)
    else:
        if Target == 'Mega':
            for i in TgtPrefixList:
                S.sendline('delete firewall family inet filter acl-BDR-IN term SEC from destination-address ' + i)
                S.expect('\{master\}')
                DisplayText(S.before, S.after, RouterIP, CQ)
        else:
            S.sendline('delete firewall family inet filter acl-BDR-IN term SEC from destination-address ' + Target)
            S.expect('\{master\}')
            DisplayText(S.before, S.after, RouterIP, CQ)

### Backend Function
def ConfigRouter(data, CQ, VAR, Target, RouterIP, OTP):
    ScriptError = ''
    S = None
    try:
        InitData = GetRoutes('', CQ, RouterIP, 'FirstPass', OTP, '')
        S = InitData[0]
        IspIpAsnList = InitData[1]
        DeviceConfigList = InitData[2]
        BdrAclList = InitData[3]
        AclSecList = InitData[4]
        GroupList = []
        E = -1
        for i in IspIpAsnList:
            E = E + 1
            PeerTerm = re.compile('set protocols bgp group .* neighbor ' + IspIpAsnList[E][0])
            for j in DeviceConfigList:
                match = PeerTerm.search(j)
                if match:
                    TempList = j.split()
                    GroupList.append(TempList)

        UniqGroupList = []
        E = -1
        for i in GroupList:
            E = E + 1
            UniqGroupList.append(GroupList[E][4])

        UniqGroupList = list(set(UniqGroupList))

        ExportList = []
        E = -1
        for i in UniqGroupList:
            E = E + 1
            GroupTerm = re.compile('set protocols bgp group ' + UniqGroupList[E] + ' export')
            for j in DeviceConfigList:
                match = GroupTerm.search(j)
                if match:
                    TempList = j.split()
                    ExportList.append(TempList)

        FirstTerms = []
        E = -1
        for i in ExportList:
            E = E + 1
            TempList = []
            TermTerm = re.compile('set policy-options policy-statement ' + ExportList[E][6] + ' term \S+')
            for j in DeviceConfigList:
                Match = TermTerm.search(j)
                if Match:
                    TempList.append(Match.group().split())
            FirstTerms.append(TempList[0])

        S.sendline("configure exclusive")
        S.expect(RouterIP + '#')
        DisplayText(S.before, S.after, RouterIP, CQ)
        if VAR == 'Stop':
            StopAnnConfig(Target, ExportList, FirstTerms, S, RouterIP, CQ)
        if VAR == 'Start':
            StartAnnConfig(Target, S, RouterIP, CQ)
        if VAR == 'BlackAdd':
            AdBlackTriggerConfig(Target, S, RouterIP, CQ)
        if VAR == 'BlackRm':
            RmBlackTriggerConfig(Target, S, RouterIP, CQ)
        if VAR == 'LocalAdd':
            AddLocalFilter(Target, BdrAclList, S, RouterIP, CQ)
        if VAR == 'LocalRm':
            RmLocalFilter(Target, AclSecList, S, RouterIP, CQ)
        if VAR == 'LocalRmGoingSpounge':
            if TgtPrefixList:
                RmLocalFilter(Target, AclSecList, S, RouterIP, CQ)
            StopAnnConfig(Target, ExportList, FirstTerms, S, RouterIP, CQ)
        if VAR == 'SpoungeGoingBlack':
            StartAnnConfig(Target, S, RouterIP, CQ)
            AdBlackTriggerConfig(Target, S, RouterIP, CQ)
        if VAR == 'SpoungeGoingLocal':
            StartAnnConfig(Target, S, RouterIP, CQ)
            AddLocalFilter(Target, BdrAclList, S, RouterIP, CQ)
        if VAR == 'LocalGoingBlack':
            RmLocalFilter(Target, AclSecList, S, RouterIP, CQ)
            AdBlackTriggerConfig(Target, S, RouterIP, CQ)
        if VAR == 'BlackGoingLocal':
            RmBlackTriggerConfig(Target, S, RouterIP, CQ)
            AddLocalFilter(Target, BdrAclList, S, RouterIP, CQ)
        ### commented out for testing!!! 
        S.sendline('commit')
        S.expect('\{master\}')
        DisplayText(S.before, S.after, RouterIP, CQ)
        #### Need to integrate config error issue with GUI ### 
        ConfigError = 0
        S.sendline('exit')
        S.expect('\{master\}|\(yes\)')
        #S.expect('Exiting configuration mode|\(yes\)')
        DisplayText(S.before, S.after, RouterIP, CQ)
        if 'uncommitted changes' in bytes.decode(S.before):
            ConfigError = 1
            print('!!! ERROR !!! Configuration is uncommitted !!!')
            S.sendline('yes')
            S.expect('>')
            DisplayText(S.before, S.after, RouterIP, CQ)

        ReturnData = GetRoutes('', CQ, RouterIP, 'SecondPass', OTP, S)
        #CQ.put('END_OF_SSH_SESSION')
        data.put(ReturnData)
    except:
        ScriptError = str(sys.exc_info())
        if S:
            S.close()
        print(ScriptError)
        ReturnData = ('', '', '', '', ScriptError)
        #/CQ.put('END_OF_SSH_SESSION')
        data.put(ReturnData)
#####################################################################################################
### Frontend
#####################################################################################################

CurPopVar = None

def FormatPrefixList(PrefixList):
    global FormatedPrefixList
    FormatedPrefixList = ''
    E = -1
    for i in PrefixList:
        E = E + 1
        F = -1
        Depth = len(PrefixList[E]) - 1
        for j in PrefixList[E]:
            F = F + 1
            if F == 0:
                FormatedPrefixList = FormatedPrefixList + (PrefixList[E][F] + ": ")
            elif (Depth - F) == 0:
                FormatedPrefixList = FormatedPrefixList + (PrefixList[E][F] + "\n")
            else:
                FormatedPrefixList = FormatedPrefixList + (PrefixList[E][F] + ", ")

def ProcessPrefixList(POP):
    global PrefixList
    global SecBlockButtonList
    global FormatedSecBlock
    global FormatedBlackRoutes
    global BlackButtonList
    global FormatedLocalFilter
    global LocalButtonList
    ### Prefix List
    PrefixList = []
    NewPrefixList = []
    for i in AggPrefixList:
        Route = i[0]
        temp = []
        for j in AggPrefixList:
            E = 0
            if Route in j:
                E = -1
                for h in j:
                    E = E + 1
                    if E != 0:
                        temp.append(j[E])
        temp = list(set(temp))
        temp.insert(0, Route)
        NewPrefixList.append(temp)
    VooDoo = set(map(tuple, NewPrefixList))
    for i in VooDoo:
        PrefixList.append(list(i))
    PrefixList.sort()
    ### Add advertising routers ###
    for i in RtrList:
        if POP == i[0]:
            R1name = (i[1].split('-'))[0]
            R2name = (i[2].split('-'))[0]
            break
    for i in PrefixList:
        R1 = ''
        R2 = ''
        Zulu = i[0]
        for j in RtrOne[0]:
            if Zulu in j[0]:
                R1 = 'Yes'
                break
        for k in RtrTwo[0]:
            if Zulu in k[0]:
                R2 = 'Yes'
                break
        if (R1 == 'Yes') and (R2 == 'Yes'):
            rStatus = '(both)'
        elif R1 == 'Yes':
            rStatus = ("(" + R1name + ")")
        elif R2 == 'Yes':
            rStatus = ("(" + R2name + ")")
        i.append(rStatus)
    ### SecBlockList aka announcement stopped
    TempList = []
    SecBlockButtonList = []
    FormatedSecBlock = ''
    try:
        for i in AggSecPrefixList:
                TempList.append(i[4])
                TempList = list(set(TempList))
        for j in TempList:
            FormatedSecBlock = (FormatedSecBlock + j + '\n')
            SecBlockButtonList.append(j)
    except:
        pass
    if FormatedSecBlock == '':
        FormatedSecBlock = 'None Found'
    ### Black Routes
    TempList = []
    BlackButtonList = []
    FormatedBlackRoutes = ''
    for i in AggBlackRoutes:
        TempList.append(i.split()[4])
        TempList = list(set(TempList))
    for j in TempList:
        FormatedBlackRoutes = (FormatedBlackRoutes + j + '\n')
        BlackButtonList.append(j)
    if FormatedBlackRoutes == '':
        FormatedBlackRoutes = 'None Found'
    ### AclSecList aka local filter
    TempList = []
    LocalButtonList = []
    FormatedLocalFilter = ''
    for i in AggAclSecList:
        TempList.append(i[10])
        TempList = list(set(TempList))
    for i in TempList:
        FormatedLocalFilter =  (FormatedLocalFilter +  i + '\n')
        LocalButtonList.append(i)
    if FormatedLocalFilter == '':
        FormatedLocalFilter = 'None Found'

def ButtonGen(Bx, By, POP, List, Action, Command, CAction):
    if List:
        for i in List:
            Prefix = i
            By = By + 30
            Central.create_window((Bx, By), window=(Button(text=(Action + ' ' + i), bg='skyblue', activebackground='green', command=lambda POP=POP, Prefix=Prefix, CAction=CAction :Command(POP, Prefix, CAction))), anchor='nw', tag='TestPop')
    
def PrefixButtonGen(Bx, By, POP, CurPos, List):
    for i in List:
        Prefix = i
        By = By + 30
        Central.create_window((Bx, By), window=(Button(text=(i), bg='skyblue', activebackground='green', command=lambda POP=POP, Prefix=Prefix :PrefixOption(POP, Prefix, CurPos))), anchor='nw', tag='TestPop')

def PrefixOption(POP, Prefix, CurPos):
    Central.delete('ErrorText')
    Central.create_text((425,500), text='Available Options Are:', font=StatusFont, anchor='nw', tag='TestPop')
    if CurPos == 'LocalFilter':
        Option0 = Button(text=('Condition #0: ' + Prefix), bg='skyblue', activebackground='green', command=lambda POP=POP, Prefix=Prefix, :PrepLocalRemove(POP, Prefix)) ### remove action
        Option2 = Button(text=('Condition #2: ' + Prefix), bg='burlywood', activebackground='firebrick', command=lambda POP=POP, Prefix=Prefix, :PrepLocalGoingSpounge(POP, Prefix))
        Option3 = Button(text=('Condition #3: ' + Prefix), bg='red', activebackground='orange', command=lambda POP=POP, Prefix=Prefix, :PrepLocalGoingBlack(POP, Prefix))
        Central.create_window((425,530), window=Option0, anchor='nw', tag='TestPop')
        if POP != 'P28-NRT':
            Central.create_window((425,560), window=Option2, anchor='nw', tag='TestPop')
        Central.create_window((425,590), window=Option3, anchor='nw', tag='TestPop')
    if CurPos == 'StopAnn':
        Option0 = Button(text=('Condition #0: ' + Prefix), bg='skyblue', activebackground='green', command=lambda POP=POP, Prefix=Prefix, :GatherOTP(POP, Prefix, 'Start')) ### remove action
        Option1 = Button(text=('Condition #1: ' + Prefix), bg='burlywood', activebackground='firebrick', command=lambda POP=POP, Prefix=Prefix, :StopGoingCrazy(POP, Prefix, 'GoingLocal'))
        Option3 = Button(text=('Condition #3: ' + Prefix), bg='red', activebackground='orange', command=lambda POP=POP, Prefix=Prefix, :StopGoingCrazy(POP, Prefix, 'GoingBlack'))
        Central.create_window((425,530), window=Option0, anchor='nw', tag='TestPop')
        Central.create_window((425,560), window=Option1, anchor='nw', tag='TestPop')
        Central.create_window((425,590), window=Option3, anchor='nw', tag='TestPop')
    if CurPos == 'BlackHole':
        Option0 = Button(text=('Condition #0: ' + Prefix), bg='skyblue', activebackground='green', command=lambda POP=POP, Prefix=Prefix, :GatherOTP(POP, Prefix, 'BlackRm')) ### remove action
        Option1 = Button(text=('Condition #1: ' + Prefix), bg='burlywood', activebackground='firebrick', command=lambda POP=POP, Prefix=Prefix, :GatherOTP(POP, Prefix, 'BlackGoingLocal'))
        Central.create_window((425,530), window=Option0, anchor='nw', tag='TestPop')
        Central.create_window((425,560), window=Option1, anchor='nw', tag='TestPop')
    CancelButton = Button(text='Cancel and Refesh', anchor='nw', bg='green', activebackground='olivedrab', command=lambda POP=POP :Canx(POP))
    Central.create_window((425, 620), window=CancelButton, anchor='nw', tag='TestPop')

def StopGoingCrazy(POP, Prefix, Where):
    global HostAdds
    if Where == 'GoingLocal':
        Tvar = 'Local Filter'
    if Where == 'GoingBlack':
        Tvar = 'Black Hole'
    HostAdds = StringVar()
    Central.create_text((425, 655), text='Enter Host Addresses to ' + Tvar + ' below:', font=StatusFont, anchor='nw', tag='TestPop')
    EntHosts = Entry(font=CurMedFont, textvariable=HostAdds, width=56)
    Central.create_window((425, 680), window=EntHosts, anchor='nw', tag='TestPop')
    ValidateHosts = Button(text='Validate Host Address(es) & Continue', font=CurMedFont, bg='skyblue', activebackground='green', command=lambda POP=POP, Prefix=Prefix, Where=Where, :StopChanging(POP, Prefix, Where)) 
    Central.create_window((425, 720), window=ValidateHosts, anchor='nw', tag='TestPop')



def StopChanging(POP, Prefix, Where):
    global TgtPrefixList
    global StartAnnList
    Central.delete('ErrorText')
    Central.update()
    TgtPrefixList = []
    StartAnnList = []
    CandPrefixList = HostAdds.get().split()
    StartAnnList.append(Prefix)
    for i in CandPrefixList:
        Match = PrefixCheckTerm.match(i)
        if Match:
            TgtPrefixList.append(i)
        else:
            TgtPrefixList.append(i + '/32')
    for i in TgtPrefixList:
        try:
            CheckNet = IPNetwork(i).network
        except:
            print(sys.exc_info())
            IpError = sys.exc_info()
            Central.create_text((700,800), text=(IpError), font=StatusFont, fill='red', tags=('TestPop', 'ErrorText'))
            break
        if str(CheckNet) != i.split('/')[0]:
            Central.create_text((700,800), text=(i + ' is not a prefix; please try again'), font=StatusFont, fill='red', tags=('TestPop', 'ErrorText'))
        else:
            for i in TgtPrefixList:
                PrefixCheck = 0
                for j in PrefixList:
                    if IPNetwork(i) in IPNetwork(j[0]):
                        PrefixCheck = 1
                        break
                for j in SecBlockButtonList:
                    if IPNetwork(i) in IPNetwork(j):
                        PrefixCheck = 1
                        break
                if PrefixCheck == 0:
                    print(i + ' is not within the annoucement range of this POP')
                    Central.create_text((700,800), text=(i + ' is not within the announcement range of the POP'), font=StatusFont, fill='red', tags=('TestPop', 'ErrorText'))
                    break
    if PrefixCheck == 1:
        for i in TgtPrefixList:
            PrefixCheck = 0
            if IPNetwork(i) not in IPNetwork(Prefix):
                Central.create_text((700,800), text=(i + ' is not within network ' + Prefix), font=StatusFont, fill='red', tags=('TestPop', 'ErrorText'))
                break
            else:
                PrefixCheck = 1
    if PrefixCheck == 1:
        Central.create_text((700,800), text=('Validated!!!'), font=StatusFont, fill='green', tags=('TestPop'))
        print('#######')
        print(Prefix)
        print(TgtPrefixList)
        print('#######')
    if Where == 'GoingLocal':
        GatherOTP(POP, 'Mega', 'SpoungeGoingLocal')
    if Where == 'GoingBlack':
        GatherOTP(POP, 'Mega', 'SpoungeGoingBlack')
    

def Canx(POP):
    Central.delete('TestPop')
    TestPopPage(POP)

def PrepLocalGoingBlack(POP, Target):
    global TgtPrefixList
    TgtPrefixList = []
    GatherOTP(POP, Target, 'LocalGoingBlack')

def PrepLocalRemove(POP, Target):
    global TgtPrefixList
    TgtPrefixList = []
    GatherOTP(POP, Target, 'LocalRm')

def PrepLocalGoingSpounge(POP, Target):
    global TgtPrefixList
    global StopAnnList
    TgtPrefixList = []
    CandStopAnn = []
    TgtPrefixList.append(Target)
    for i in TgtPrefixList:
        for j in PrefixList:
            if IPNetwork(i) in IPNetwork(j[0]):
                CandStopAnn.append(j[0])
    StopAnnList = list(set(CandStopAnn))
    for i in LocalButtonList:
        for j in StopAnnList:
            if IPNetwork(i) in IPNetwork(j):
                TgtPrefixList.append(i)
    TgtPrefixList = list(set(TgtPrefixList))
    GatherOTP(POP, 'Mega', 'LocalRmGoingSpounge')
    print('#####')
    print(TgtPrefixList)
    print('######')
    print(StopAnnList)
    print('######')
    print(POP)

def GoingSpounge(POP):
    global TgtPrefixList
    global StopAnnList
    CandStopAnn = []
    for i in TgtPrefixList:
        for j in PrefixList:
            if IPNetwork(i) in IPNetwork(j[0]):
                CandStopAnn.append(j[0])
    StopAnnList = list(set(CandStopAnn))
    TgtPrefixList = [] 
    for i in LocalButtonList:
        for j in StopAnnList:
            if IPNetwork(i) in IPNetwork(j):
                TgtPrefixList.append(i)
    TgtPrefixList = list(set(TgtPrefixList))
    GatherOTP(POP, 'Mega', 'LocalRmGoingSpounge')
    print('#####')
    print(TgtPrefixList)
    print('######')
    print(StopAnnList)
    print('######')
    print(POP)



def IntroPage():
    global OTP
    Central.delete('ErrorText')
    Central.create_text((40,20), text='Security Routing Change Tool', font=LargeFont, anchor='nw', tag='Intro')
    IntroText2 = Central.create_text((40,150), text='Click the POP below for current status.', font=CurMedFont, anchor='nw',tag='Intro')

    HongKongButton = Button(text='P5-HKG', font=CurMedFont, bg='skyblue', activebackground='green', width=10, command=lambda POP='P5-HKG' :LoginCreds(POP))
    SpawnHongKongButton = Central.create_window((110, 230), window=HongKongButton, tag='Intro')

    P28NrtButton = Button(text='P28-NRT', font=CurMedFont, bg='skyblue', activebackground='green', width=10, command=lambda POP='P28-NRT' :LoginCreds(POP))
    SpawnP28NrtButton = Central.create_window((310, 230), window=P28NrtButton, tag='Intro')
    
    P4AmsButton = Button(text='P4-AMS', font=CurMedFont, bg='skyblue', activebackground='green', width=10, command=lambda POP='P4-AMS' :LoginCreds(POP))
    Central.create_window((510, 230), window=P4AmsButton, tag='Intro')

    WarningOne = Central.create_text((900,250), text='Production Test Version\nBe Careful!!', font=BigFont, fill="red", tag='Intro')
    if CurPopVar and not ScriptError:
        BackButton = Button(text='Back to Previous POP', font=CurMedFont, bg='skyblue', activebackground='green', command=lambda POP=CurPopVar :BackToPop(POP))
        SpawnBackButton = Central.create_window((30,270), window=BackButton, anchor='nw', tag='Intro')
    if ScriptError:
        Central.create_text((30,450), text=('There was a script error\nPlease try again.'), font=MedFont, fill='red', anchor='nw', tag='ErrorText')
        ErrorTextBox = Text(width=100, font=CurSmallFont)
        Central.create_window((30,525), window=ErrorTextBox, anchor='nw', tag='ErrorText')
        ErrorTextBox.insert(END, ScriptError)
        ErrorTextBox.config(state=DISABLED)
    if Qerror:
        Central.create_text((30,450), text=(Qerror), font=MedFont, fill='red', anchor='nw', tag='ErrorText')
    if InCon:
        Central.create_text((700,450), text='***  ERROR  ***', font=LargeFont, fill='red', tag='ErrorText')
        Central.create_text((700,550), text=(InCon + ' BB Router configurations are not syncronized.'), font=BigFont, fill='red', tag='ErrorText')
        Central.create_text((700,650), text='Please call Network Operations to Resolve.', font=MedFont, fill='blue', tag='ErrorText')

def BackToIntro():
    Central.delete('TestPop')
    Central.delete('TextPop')
    IntroPage()

def EgressCommand():
    sys.exit()

def BackToPop(CurPopVar):
    Central.delete('Intro')
    TestPopPage(CurPopVar)

def TestPopPage(POP):
    global OTP
    global RoutesAnnouncedData
    global CandPrefix
    global CurPopVar
    CurPopVar = POP
    Central.delete('Intro')
    MainPage = Button(text='POP\nSelection Page', bg='skyblue', activebackground='green', command=BackToIntro)
    SpawnMainPage = Central.create_window((1250,875), window=MainPage, tag='TestPop')
    
    CandPrefix = StringVar()
    PrefixDesc = Central.create_text((425,100), text='Enter the attack target prefix or IP address below:', font=CurMedFont, anchor='nw', tag='TestPop')
    EntPrefix = Entry(font=CurMedFont, textvariable=CandPrefix, width=56)
    SpawnEntPrefix = Central.create_window((425,125), window=EntPrefix, anchor='nw', tag='TestPop')
    Validate = Button(text='Check Prefix\nFor Option', font=NormFont, bg='skyblue', activebackground='green', command=lambda POP=POP : OptionStub(POP))
    SpawnValidate = Central.create_window((1175,105), window=Validate, anchor='nw', tag='TestPop')
    TestPoPText1 = Central.create_text((Mx+350,My), text=(POP + ' Status & Response Page'), font=LargeFont, tag='TestPop')
    Central.create_text((900,30), text='GRE Tunnel Status:', font=MedFont, anchor='nw', tag='TestPop', fill='blue')
    Central.create_text((1140,30), text='DOWN!', font=MedFont, anchor='nw', tag='TestPop', fill='red')
    Central.create_rectangle(885, 15, 1250, 70, tag='TestPop')
    TestPopText2 = Central.create_text((40,90), text='Current Status:', font=MedFont, anchor='nw', tag='TestPop')
    RoutesAnnounced = Central.create_text((40,130), text='Current Routes being announced', fill='green', font=NormFont, anchor='nw', tag='TestPop')
    if POP == 'P5-HKG':
         RoutesAnnouncedData = Central.create_text((40,150), text=FormatedPrefixList, anchor='nw', font=CurTinyFont, tag='TestPop')
    else:
        RoutesAnnouncedData = Central.create_text((40,150), text=FormatedPrefixList, anchor='nw', tag='TestPop')

    Central.create_text((425,190), text='Condition #1', font=NormFont, fill='red', anchor='nw', tag='TestPop')
    LocalFilter = Central.create_text((425,210), text='Traffic Shifted to Local MFD/MFI', font=NormFont, fill='red', anchor='nw', tag='TestPop')
    if not LocalButtonList:
        Central.create_text((425,235), text='None Found', anchor='nw', tag='TestPop')
    else:
        PrefixButtonGen(425, 205, POP, 'LocalFilter', LocalButtonList)
    
    Central.create_text((725,190), text='Condition #2', font=NormFont, fill='red', anchor='nw', tag='TestPop')
    SecBlock = Central.create_text((725,210), text='Traffic Shifted to Remote BFD/MFI', font=NormFont, fill='red', anchor='nw', tag='TestPop')
    if POP == 'P28-NRT':
        Central.create_text((725,235), text='Not possible\nThis is a Sponge POP.', anchor='nw', tag='TestPop')
    if (not SecBlockButtonList) and (POP != 'P28-NRT'):
        Central.create_text((725,235), text='None Found', anchor='nw', tag='TestPop')
    else:
        PrefixButtonGen(725, 205, POP, 'StopAnn', SecBlockButtonList)

    Central.create_text((1025,190), text='Condition #3', font=NormFont, fill='red', anchor='nw', tag='TestPop')
    BlackHole = Central.create_text((1025, 210), text='Black Hole Routed', font=NormFont, fill='red', anchor='nw', tag='TestPop')
    if not BlackButtonList:
        Central.create_text((1025,235), text='None Found', anchor='nw', tag='TestPop')
    else:
        PrefixButtonGen(1025, 205, POP, 'BlackHole', BlackButtonList)

    RefreshButton = Button(text='Refresh POP Data', font=CurMedFont, bg='skyblue', activebackground='green', command=lambda POP=POP :LoginCreds(POP))
    SpawnRefreshButton = Central.create_window((935,855), window=RefreshButton, anchor='nw', tag='TestPop')

def OptionStub(POP):
    global OTP
    global CandPrefixList
    global TgtPrefixList
    global OptionMatrix
    global StopAnnList
    global StartAnnList
    global IpError
    Central.delete('ErrorText')
    Central.update()
    TgtPrefixList = []
    CandPrefixList = CandPrefix.get().split()
    for i in CandPrefixList:
        Match = PrefixCheckTerm.match(i)
        if Match:
            TgtPrefixList.append(i)
        else:
            TgtPrefixList.append(i + '/32')
    for i in TgtPrefixList:
        try:
            CheckNet = IPNetwork(i).network
        except:
            print(sys.exc_info())
            IpError = sys.exc_info()
            Central.create_text((700,800), text=(IpError), font=StatusFont, fill='red', tags=('Intro', 'ErrorText')) 
            break
        if str(CheckNet) != i.split('/')[0]:
            Central.create_text((700,800), text=(i + ' is not a prefix; please try again'), font=StatusFont, fill='red', tags=('Intro', 'ErrorText'))
        else:
            for i in TgtPrefixList:
                PrefixCheck = 0
                for j in PrefixList:
                    if IPNetwork(i) in IPNetwork(j[0]):
                        PrefixCheck = 1
                        break
                for j in SecBlockButtonList:
                    if IPNetwork(i) in IPNetwork(j):
                        PrefixCheck = 1
                        break
                if PrefixCheck == 0:
                    print(i + ' is not within the annoucement range of this POP')
                    Central.create_text((700,800), text=(i + ' is not within the announcement range of the POP'), font=StatusFont, fill='red', tags=('Intro', 'ErrorText'))
                    break
            if PrefixCheck == 1:
                OptionMatrix = []
                for i in TgtPrefixList:
                    OptionStatus = ''
                    print(i)
                    for j in LocalButtonList:
                        if i == j:
                            OptionStatus = 'CurLocalFilter'
                    for j in SecBlockButtonList:
                        if IPNetwork(i) in IPNetwork(j):
                            OptionStatus = 'CurSpoungePop'
                    for j in BlackButtonList:
                        if i == j:
                            OptionStatus = 'CurBlackHole'    
                    if OptionStatus == '':   
                        OptionStatus = 'CurNone' 
                    OptionMatrix.append([i, OptionStatus])
                Sameness = 1
                for i in OptionMatrix:
                    for k in OptionMatrix:
                        if i[1] != k[1]:
                            Sameness = 0
                if Sameness == 0:
                    print('differnt')
                    Central.create_text((700,800), text=('These prefixes have differnt security postures\nand cannot be grouped together.'), font=StatusFont, fill='red', tags=('Intro', 'ErrorText'))
                else:
                    print('same')
                    Central.create_text((425,500), text='Available Options Are:', font=StatusFont, anchor='nw', tag='TestPop')
                    CurStatus = OptionMatrix[0][1]
                    if CurStatus == 'CurNone':
                        Option1 = Button(text=('Condition #1 ' + CandPrefix.get()), bg='red', activebackground='orange', command=lambda POP=POP, Prefix='Mega', CAction='LocalAdd' :GatherOTP(POP, Prefix, CAction))
                        Option2 = Button(text=('Condition #2 ' + CandPrefix.get()), bg='burlywood', activebackground='firebrick', command=lambda POP=POP :GoingSpounge(POP))
                        Option3 = Button(text=('Condition #3 ' + CandPrefix.get()), bg='red', activebackground='orange', command=lambda POP=POP, Prefix='Mega', CAction='BlackAdd' :GatherOTP(POP, Prefix, CAction))
                        Central.create_window((425,530), window=Option1, anchor='nw', tag='TestPop')
                        if POP != 'P28-NRT':
                            Central.create_window((425,560), window=Option2, anchor='nw', tag='TestPop')
                        Central.create_window((425,590), window=Option3, anchor='nw', tag='TestPop')
                        CancelButton = Button(text='Cancel and Refesh', anchor='nw', bg='green', activebackground='olivedrab', command=lambda POP=POP :Canx(POP))
                        Central.create_window((425, 620), window=CancelButton, anchor='nw', tag='TestPop')
                    if (CurStatus == 'CurLocalFilter') and (POP != 'P28-NRT'):
                        Central.create_text((425,530), text=('Please click on the appropriate prefix in Condtion #1 to reroute this host.'), font=StatusFont, fill='red', anchor='nw', tags=('Intro', 'ErrorText'))
                        CancelButton = Button(text='Cancel and Refesh', anchor='nw', bg='green', activebackground='olivedrab', command=lambda POP=POP :Canx(POP))
                        Central.create_window((425, 620), window=CancelButton, anchor='nw', tag='TestPop')
                    
                    if (CurStatus == 'CurLocalFilter') and (POP == 'P28-NRT'):
                        Central.create_text((425,530), text=('Please click on the appropriate prefix in Condtion #1 to reroute this host.'), font=StatusFont, fill='red', anchor='nw', tags=('Intro', 'ErrorText'))
                        CancelButton = Button(text='Cancel and Refesh', anchor='nw', bg='green', activebackground='olivedrab', command=lambda POP=POP :Canx(POP))
                        Central.create_window((425, 620), window=CancelButton, anchor='nw', tag='TestPop')

                    if CurStatus == 'CurSpoungePop':
                        Central.create_text((425,530), text=('Please click on the appropriate prefix in Condtion #2 to reroute this host.'), font=StatusFont, fill='red', anchor='nw', tags=('Intro', 'ErrorText'))
                        CancelButton = Button(text='Cancel and Refesh', anchor='nw', bg='green', activebackground='olivedrab', command=lambda POP=POP :Canx(POP))
                        Central.create_window((425, 620), window=CancelButton, anchor='nw', tag='TestPop')
                    if CurStatus == 'CurBlackHole':
                        Central.create_text((425,530), text=('Please click on the appropriate prefix in Condtion #3 to reroute this host.'), font=StatusFont, fill='red', anchor='nw', tags=('Intro', 'ErrorText'))
                        CancelButton = Button(text='Cancel and Refesh', anchor='nw', bg='green', activebackground='olivedrab', command=lambda POP=POP :Canx(POP))
                        Central.create_window((425, 620), window=CancelButton, anchor='nw', tag='TestPop')


def DualInsanity(CQ1, CQ2):
    r1Data = ''
    r2Data = ''
    RTR1TextBox = Text(width=100, height=35, font=CurTinyFont)
    RTR2TextBox = Text(width=100, height=35, font=CurTinyFont)
    Central.create_window((30,300), window=RTR1TextBox, anchor='nw', tags=('Intro', 'TextPop'))
    Central.create_window((690,300), window=RTR2TextBox, anchor='nw', tags=('Intro', 'TextPop'))
    while True:
        try:
            if (J1.exitcode == None) or (J2.exitcode == None):
                if (r1Data == 'END_OF_SSH_SESSION') and (r2Data == 'END_OF_SSH_SESSION'):
                    break
                if r1Data != 'END_OF_SSH_SESSION':
                    r1Data = CQ1.get()
                    RTR1TextBox.config(state=NORMAL)
                    RTR1TextBox.insert(END, (r1Data + '\n'))
                    RTR1TextBox.see('end')
                    RTR1TextBox.config(state=DISABLED)
                if r2Data != 'END_OF_SSH_SESSION':
                    r2Data = CQ2.get()
                    RTR2TextBox.config(state=NORMAL)
                    RTR2TextBox.insert(END, (r2Data + '\n'))
                    RTR2TextBox.see('end')
                    RTR2TextBox.config(state=DISABLED)
                Central.update()
            else:
                break
        except:
            print(sys.exc_info())
            break


def ContinueFromDiff(POP):
    Central.delete('TestPop')
    Central.update()
    TestPopPage(POP)


def DisplayDiff(R1, R2, POP):
    Central.delete('TestPop', 'Intro')
    RtrOneDiff = GetDiff(R1)
    RtrTwoDiff = GetDiff(R2)
    RTR1TextBox = Text(width=100, height=35, font=CurTinyFont)
    RTR2TextBox = Text(width=100, height=35, font=CurTinyFont)
    Central.create_window((30,300), window=RTR1TextBox, anchor='nw', tags=('Intro', 'TextPop'))
    Central.create_window((690,300), window=RTR2TextBox, anchor='nw', tags=('Intro', 'TextPop'))
    RTR1TextBox.insert(END, ('######## Configuratoin Diff For: ' + R1 + ' ########\n'))
    RTR2TextBox.insert(END, ('######## Configuration Diff For: ' + R2 + ' ########\n'))
    RTR1TextBox.insert(END, '\n')
    RTR2TextBox.insert(END, '\n')
    for i in RtrOneDiff:
        RTR1TextBox.insert(END, i)
    for i in RtrTwoDiff:
        RTR2TextBox.insert(END, i)
    ContinueButton = Button(text='Click to Continue', font=CurMedFont, bg='green', activebackground='skyblue', command=lambda POP=POP :ContinueFromDiff(POP))
    Central.create_window((680,750), window=ContinueButton, tags=('Intro', 'TextPop'))
    Central.update()

def FormatDiffList(List):
    Status = 0
    K = -1 
    for i in List:
        K = K + 1
        if 'set version' in i:
            Status = 1
        if Status == 0:
            del List[K]
            K = K - 1
        else:
            i = i + '\n' 
            List[K] = i

def GetDiff(RTR):
    File = open(RTR + '.txt')
    Text = File.read()
    TextList = Text.split('{master}')

    ParseList = []
    for i in TextList:
        if 'show configuration | display set' in i:
            ParseList.append(i)

    BeforeList = ParseList[0].splitlines()
    AfterList = ParseList[1].splitlines()

    FormatDiffList(BeforeList)
    FormatDiffList(AfterList)

    Diff = (context_diff(BeforeList, AfterList, fromfile='Before', tofile='After'))

    FormatDiff = list(Diff)

    return(FormatDiff)
 

def GatherOTP(POP, Prefix, CAction):
    global OTP
    Central.delete('ErrorText')
    Central.update()
    OTP = None
    OTP = StringVar()
    OtpText = Central.create_text((700,500), text='Enter OTP:', font=CurMedFont, anchor='nw', tag='TestPop')
    OtpBox = Entry(font=CurMedFont, textvariable=OTP, width=6)
    SpawnOtpBox = Central.create_window((830,500), window=OtpBox, anchor='nw', tag='TestPop')
    ContButton = Button(text='Continue', font=NormFont, bg='red', activebackground='orange', command=lambda POP=POP, Prefix=Prefix, CAction=CAction :StartAnn(POP, Prefix, CAction))
    SpawnContButton = Central.create_window((830,550), window=ContButton, anchor='nw', tag='TestPop')

def CheckFile(RTR):
    CurFiles = os.listdir()
    for i in CurFiles:
        if i == (RTR + '.txt'):
            os.unlink(i)

def StartAnn(POP, Target, CAction):
    global ScriptError
    global Qerror
    global RtrOne
    global RtrTwo
    global AggPrefixList
    global AggSecPrefixList
    global AggBlackRoutes
    global AggAclSecList    
    global J1
    global J2
    global InCon
    Qerror = None
    ScriptError = None
    InCon = None
    RtrOne = ''
    RtrTwo = ''
    Central.create_text((25,875), text='Script is running!!! Please wait....', font=StatusFont, fill='red', anchor='nw', tags=('Intro'))
    Central.update()
    E = -1
    for i in RtrList:
        E = E + 1
        if POP in RtrList[E][0]:
            CheckFile(RtrList[E][1])
            CheckFile(RtrList[E][2])
            Q1 = Queue()
            Q2 = Queue()
            #CQ1 = Queue()
            #CQ2 = Queue()
            J1 = Process(target=ConfigRouter, args=(Q1, '', CAction, Target, RtrList[E][1], OTP.get()))
            J2 = Process(target=ConfigRouter, args=(Q2, '', CAction, Target, RtrList[E][2], OTP.get()))
            J1.start()
            time.sleep(2)
            J2.start()
            #DualInsanity(CQ1, CQ2)
            RtrOne = Q1.get()
            RtrTwo = Q2.get()
            J1.join()
            J2.join()
            break
    D = 0
    try:
        for i in range(3):
            D = D + 1
            if RtrOne[D] != RtrTwo[D]:
                InCon = POP
                break
    except:
        print('There may be a child process queue read problem....')
        print(sys.exc_info())
        Central.delete('Intro', 'TestPop')
        Qerror = 'There was an error with the SSH process queue... Please try again.'
        pass
    if not Qerror:
        if RtrOne[4] or RtrTwo[4]:
            ScriptError = ('########################## ' +  RtrList[E][1] + ' #############################\n' + RtrOne[4] + '\n\n############################ ' +RtrList[E][2] + ' #########################\n' + RtrTwo[4])
            Central.delete('Intro', 'TestPop')
            InCon = None
            IntroPage()
        elif InCon:
            Central.delete('Intro', 'TestPop')
            IntroPage()
        else:
            AggPrefixList = RtrOne[0] + RtrTwo[0]
            AggSecPrefixList = RtrOne[1] + RtrTwo[1]
            AggBlackRoutes = RtrOne[2] + RtrTwo[2]
            AggAclSecList = RtrOne[3] + RtrTwo[3]
            ProcessPrefixList(POP)
            FormatPrefixList(PrefixList)
            DisplayDiff(RtrList[E][1], RtrList[E][2], POP)
            #Central.delete('TestPop')
            #Central.update()
            #TestPopPage(POP)
    else:
        IntroPage()

def InitiateProdPop(POP):
    global ScriptError
    global RtrOne
    global RtrTwo
    global AggPrefixList
    global AggPrefixList
    global AggSecPrefixList
    global AggBlackRoutes
    global AggAclSecList
    global J1
    global J2
    global InCon
    ScriptError = None
    InCon = None
    RtrOne = ''
    RtrTwo = ''
    Central.delete('TestPop')
    Central.delete('ErrorText')
    Central.create_text((25,875), text='Script is running!!! Please wait....', font=StatusFont, fill='red', anchor='nw', tags=('Intro', 'ScriptRunning'))
    Central.update()
    E = -1
    for i in RtrList:
        E = E + 1
        if POP in RtrList[E][0]:
            CheckFile(RtrList[E][1])
            CheckFile(RtrList[E][2])
            Q1 = Queue()
            Q2 = Queue()
            #CQ1 = Queue()
            #CQ2 = Queue()
            J1 = Process(target=GetRoutes, args=(Q1, '', RtrList[E][1], '1', OTP.get(), ''))
            J2 = Process(target=GetRoutes, args=(Q2, '', RtrList[E][2], '1', OTP.get(), ''))
            J1.start()
            time.sleep(2)
            J2.start()
            #DualInsanity(CQ1, CQ2)
            #bogon = CQ1.get()
            #bogon = CQ2.get()
            RtrOne = Q1.get()
            RtrTwo = Q2.get()
            J1.join()
            J2.join()
            break
    D = 0
    try:
        for i in range(3):
            D = D + 1
            if RtrOne[D] != RtrTwo[D]:
                InCon = POP
                break
    except:
        print('There may be a child process queue read problem....')
        print(sys.exc_info())
        pass 
    if RtrOne[4] or RtrTwo[4]:
        ScriptError = ('########################## ' +  RtrList[E][1] + ' #############################\n' + RtrOne[4] + '\n\n############################ ' + RtrList[E][2] + ' #########################\n' + RtrTwo[4])
        Central.delete('Intro', 'TestPop')
        InCon = None
        IntroPage()
    elif InCon:
        Central.delete('Intro', 'TestPop')
        IntroPage()
    else:   
        AggPrefixList = RtrOne[0] + RtrTwo[0]
        AggSecPrefixList = RtrOne[1] + RtrTwo[1]
        AggBlackRoutes = RtrOne[2] + RtrTwo[2]
        AggAclSecList = RtrOne[3] + RtrTwo[3]
        ProcessPrefixList(POP)
        FormatPrefixList(PrefixList)
        Central.update()
        TestPopPage(POP) 
 
def LoginCreds(POP):
    global UserVar
    global PassVar
    global OTP
    global GuiKeyFile
    global KssServer
    OTP = None
    OTP = StringVar()
    Central.delete('TestPop', 'ErrorText', 'TextPop')

    if not CurPopVar:
        UserVar = StringVar()
        PassVar = StringVar()
        GuiKeyFile = StringVar()
        KssServer = StringVar()
        CredText = Central.create_text((40,330), text='Please enter your KSS credentials below.', font=MedFont, anchor='nw', tag='Intro')

        KeyFileText = Central.create_text((45,385), text='KSS Key File:', font=CurSmallFont, anchor='nw', tag='Intro')
        KeyFileEntry = Entry(font=CurMedFont, textvariable=GuiKeyFile)
        KeyFileEntrySpawn = Central.create_window((170,375), window=KeyFileEntry, anchor='nw', tag='Intro')

        UserEntryText = Central.create_text((40,420), text='Username:', font=CurMedFont, anchor='nw', tag='Intro')
        UserEntry = Entry(font=CurMedFont, textvariable=UserVar)
        UserEntrySpawn = Central.create_window((170,420), window=UserEntry, anchor='nw', tag='Intro')

        UserPassText = Central.create_text((40,465), text='Password:', font=CurMedFont, anchor='nw', tag='Intro')
        UserPassEntry = Entry(font=CurMedFont, textvariable=PassVar, show="*")
        UserPassEntrySpawn = Central.create_window((170,465), window=UserPassEntry, anchor='nw', tag='Intro')
        
        KrKssRadio = Radiobutton(text='KR-KSS', font=CurMedFont, variable=KssServer, value='kss-kr.cdngp.net')
        SpawnKrKssRadio = Central.create_window((460,375), window=KrKssRadio, anchor='nw', tag='Intro')

        JpKssRadio = Radiobutton(text='JP-KSS', font=CurMedFont, variable=KssServer, value='kss-jp.cdngp.net')
        SpawnJpKssRadio = Central.create_window((460,420), window=JpKssRadio, anchor='nw', tag='Intro')

        UsKssRadio = Radiobutton(text='US-KSS', font=CurMedFont, variable=KssServer, value='kss-us.cdngp.net')
        SpawnUsKssRadio = Central.create_window((460,465), window=UsKssRadio, anchor='nw', tag='Intro')
    else:
        OTPOnlyText = Central.create_text((40,465), text='Please enter your OTP to continue.', anchor='nw', tag='Intro', font=CurMedFont)

    OtpText = Central.create_text((104,510), text='OTP:', font=CurMedFont, anchor='nw', tag='Intro')
    OtpEntry = Entry(font=CurMedFont, textvariable=OTP, width=6)
    OtpEntrySpawn = Central.create_window((170,510), window=OtpEntry , anchor='nw', tag='Intro')

    ContButton = Button(text='Click to Continue', font=NormFont, bg='red', activebackground='orange', command=lambda POP=POP :InitiateProdPop(POP))
    ContButtonSpawn = Central.create_window((150,555), window=ContButton, tag='Intro', anchor='nw')
    


######################################################################################
### tkinter setup
######################################################################################

root = Tk()
root.title("BGP Automation Tool- UNDER DEVELOPMENT")

Central = Canvas(root, width=1400, height=900)
Central.grid()

LargeFont = font.Font(size=36)
BigFont = font.Font(size=24)
MedFont = font.Font(size=18)
NormFont = font.Font(size=12)
CurMedFont = font.Font(family='Courier', size=16)
CurSmallFont = font.Font(family='Courier', size=10)
CurTinyFont = font.Font(family='Courier', size=8)
StatusFont = font.Font(family='Courier', size=14, weight="bold")

Egress = Button(text='EXIT', font=CurMedFont, bg='skyblue', activebackground='red', command=EgressCommand)
SpawnEgress = Central.create_window((1350,875), window=Egress)

IntroPage()

root.mainloop()
