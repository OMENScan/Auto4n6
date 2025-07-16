#!/usr/bin/env python
####################################################################### 
# Version: beta v.01 (Python 3.x)                                     #
# Author.: David Porco                                                #
# Release: NA                                                         #
#                                                                     #
#   Read parsed CSV Files and convert to Timesketch format            #
#                                                                     #
#   v0.01 - Basic Ideas                                               #
#   v0.02 - Add SRUM                                                  #
#   v0.03 - Add NoData fields if the input is blank                   #
####################################################################### 
import os, stat
import sys
import csv
import time 
import argparse
import ctypes
import requests
import glob
import shutil
import datetime
from zipfile import ZipFile

parser = argparse.ArgumentParser(description="Format Triage Collection Output for Timesketch")
parser.add_argument("-d", dest="dirname", 
                  help="Triage CSV Collection Directory Name")
parser.add_argument("-c", dest="cfgname", default="ts_Transform.cfg", 
                  help="Timesketch Triage Transform Configuration File")
args = parser.parse_args()


###########################################################################
# Configuration                                                           #
###########################################################################
cfgname = str(args.cfgname)
dirname = str(args.dirname)
dirleft, diright = os.path.split(dirname)
dirtrge = dirleft + "\\Timelines\\" + diright


###########################################################################
# Main 
###########################################################################
def main():
    if dirname != "None":
        if os.path.exists(dirname):
            print("[+] Valid Timeline CSV Directory Found.\n")
        else:
            print("[!] No Valid Timeline CSV Directory Found.\n")
            sys.exit(1)
    else:
        print("[!] No Valid Timeline CSV Directory Found.\n")
        sys.exit(1)


    print("[+] Root Timeline Dir: \\Timelines\\" + diright)
    print("[+] Triage Directory: " + dirtrge)


    ###########################################################################
    # Get the local time zone - some utils use local instead of UTC           #
    ###########################################################################
    now = datetime.datetime.now()
    local_now = now.astimezone()
    local_tz = local_now.tzinfo
    local_tzname = local_tz.tzname(local_now)
    print("[+] Local Times Zone: " + local_tzname)

    GotDepend = 1  # Placeholder for future use

    ###########################################################################
    # Fell Through - Look for Config File                                     #
    ###########################################################################
    RunAllAll = 0
    RunFBrHst = RunPCAsst = RunPrfHst = RunIBrHst = RunAutoRn = RunChnSaw = RunLastAct = RunLnkPrs = RunSrum = 1  # For future use (Turn option on and off)

    HasIOCs = 0

    SrcMFT = SrcEvtx = SrcPrf = SrcLAct = SrcLnkPrs = SrcSrum = 1  # For Future Use

    Collect = "AChoirX"
    MFTFile = "\\RawData\\MFT-C"
    Prefetc = "\\Prf"
    PCAsist = "\\PCA"
    LNKFile = "\\Lnk"
    LastAct = "\\Sys\\LastActivity.csv"
    Browser = "\\Brw\\BrowseHist.csv"
    Downlod = "\\Brw\\BrowseDown.csv"
    AutoRun = "\\Arn\\AutoRun.dat"
    EvtDir1 = "\\Evt\\WINDOWS\\System32\\winevt\\Logs"
    EvtDir2 = "\\WINDOWS\\Native\\winevt\\Logs"
    SrumDir = "\\Sys\\Sys32\\sru"
    SysRegs = "\\Reg\\Config"
    PreConv = ""
    Brander = ""

    print("[+] Checking For Config File...")
    if os.path.isfile(cfgname):
        print("[+] Config File Found (" + cfgname + "), Now Parsing Config Options...")

        cfgfile = open(cfgname, encoding='utf8', errors="replace")

        for cfgline in cfgfile:
            
            if cfgline.startswith("*"):
                pass

            if cfgline.startswith("Run:AllAll"):
                SrcMFT = 1
                RunAllAll = 1

            elif cfgline.startswith("Run:PrefetchHistory"):
                SrcPrf = 1
                RunPrfHst = 1

            elif cfgline.startswith("Run:PCAssist"):
                RunPCAsst = 1

            elif cfgline.startswith("Run:FileBrowseArchive"):
                RunFBrArc = 1

            elif cfgline.startswith("Run:FileBrowseHistory"):
                RunFBrHst = 1

            elif cfgline.startswith("Run:InetBrowseHistory"):
                RunIBrHst = 1

            elif cfgline.startswith("Run:LnkParse"):
                RunLnkPrs = 1

            elif cfgline.startswith("Run:AutoRuns"):
                RunAutoRn = 1

            elif cfgline.startswith("Run:LastActivity"):
                RunLastAct = 1

            elif cfgline.startswith("Run:Chainsaw"):
                SrcEvtx = 1
                RunChnSaw = 1

            elif cfgline.startswith("Run:Srum"):
                RunSrum = 1

            elif cfgline.startswith("MFTFile:"):
                MFTFile = cfgline[8:].strip()
                print("[+] MFT Source File: " + MFTFile)

            elif cfgline.startswith("Browser:"):
                Browser = cfgline[8:].strip()
                Downlod = os.path.dirname(Browser) + "\\BrowseDown.csv"
                print("[+] Browser History: " + Browser)
                print("[+] Browser Downloads: " + Downlod)

            elif cfgline.startswith("Collect:"):
                Collect = cfgline[8:].strip()
                print("[+] Triage Collector Data: " + Collect)

            elif cfgline.startswith("Prefetc:"):
                Prefetc = cfgline[8:].strip()
                print("[+] Prefetch Directory : " + Prefetc)

            elif cfgline.startswith("AutoRun:"):
                AutoRun = cfgline[8:].strip()
                print("[+] Collected AutoRuns: " + AutoRun)

            elif cfgline.startswith("PCAsist:"):
                PCAsist = cfgline[8:].strip()
                print("[+] Windows 11 Program Compatibility Assist Directory: " + PCAsist)

            elif cfgline.startswith("LNKFile:"):
                LNKFile = cfgline[8:].strip()
                print("[+] User LNK Files: " + LNKFile)

            elif cfgline.startswith("LastAct:"):
                LastAct = cfgline[8:].strip()
                print("[+] LastActivity View: " + LastAct)

            elif cfgline.startswith("EvtDir1:"):
                EvtDir1 = cfgline[8:].strip()
                print("[+] Event Logs Directory 1: " + EvtDir1)

            elif cfgline.startswith("EvtDir2:"):
                EvtDir2 = cfgline[8:].strip()
                print("[+] Event Logs Directory 2 (Alternate): " + EvtDir2)

            elif cfgline.startswith("SrumDir:"):
                SrumDir = cfgline[8:].strip()
                print("[+] SRUM Directory: " + SrumDir)

            elif cfgline.startswith("SysRegs:"):
                SysRegs = cfgline[8:].strip()
                print("[+] System Registries Directory: " + SysRegs)

            elif cfgline.startswith("PreConv:"):
                PreConv = cfgline[8:].strip()
                print("[+] Pre-Run Conversion Script: " + PreConv)

            elif cfgline.startswith("Brander:"):
                Brander = cfgline[8:].strip()
                print("[+] Custom Branding: " + Brander)

            elif cfgline.startswith("IOC:"):
                if HasIOCs == 0:
                    print("[+] Adding IOCs for Searching...")
                    HasIOCs = 1
                    IOCList = []
                    IOCount = []
                IOCList.append(cfgline[4:].strip().lower())
                IOCount.append(0)

    else:
        print("[!] Config File Not Found (" + cfgname + "), Default Setting Configured.")
        RunAllAll = 1


    ###########################################################################
    # Pre-Cleanup to delete any Leftover temp files from failed runs
    ###########################################################################
    print("[+] Now Deleting old ts_Transform temp files...")
    returned_value = os.system("mkdir " + dirtrge)

    ChSwSubDir = ""
    for ChName in glob.glob(dirtrge + '\\**\account_tampering.csv', recursive=True):
        os.remove(ChName)
        if ChSwSubDir == "":
            Path_File = os.path.split(ChName)
            ChSwSubDir = Path_File[0]

    for ChName in glob.glob(dirtrge + '\\**\antivirus.csv', recursive=True):
        os.remove(ChName)
        if ChSwSubDir == "":
            Path_File = os.path.split(ChName)
            ChSwSubDir = Path_File[0]

    for ChName in glob.glob(dirtrge + '\\**\lateral_movement.csv', recursive=True):
        os.remove(ChName)
        if ChSwSubDir == "":
            Path_File = os.path.split(ChName)
            ChSwSubDir = Path_File[0]

    for ChName in glob.glob(dirtrge + '\\**\log_tampering.csv', recursive=True):
        os.remove(ChName)
        if ChSwSubDir == "":
            Path_File = os.path.split(ChName)
            ChSwSubDir = Path_File[0]

    for ChName in glob.glob(dirtrge + '\\**\sigma.csv', recursive=True):
        os.remove(ChName)
        if ChSwSubDir == "":
            Path_File = os.path.split(ChName)
            ChSwSubDir = Path_File[0]

    if ChSwSubDir != "":
        ChSwLeftOvers = ChSwSubDir + "\\**\*.csv"
        for ChName in glob.glob(ChSwLeftOvers, recursive=True):
            os.remove(ChName)
        shutil.rmtree(ChSwSubDir)


    ###########################################################################
    # Prep Some files that have requirements                                  #
    ###########################################################################
    print("[+] Stabilizing Files...")

    SRUFile = dirname + SrumDir + "\\SRUDB.dat"
    print("[+] Duplicating SRUM Directory/Files...")

    ###########################################################################
    # Copy SRUM & SOFTWARE and Remove read only - It makes SrumECmd fail      #
    ###########################################################################
    if os.path.isfile(SRUFile):
        # New Version used Python shutil
        srum_files = glob.glob(dirname + "\\Cache\\*")
        for srumfile in srum_files:
            os.chmod(srumfile, stat.S_IWRITE)
            os.remove(srumfile)

        srum_files = glob.glob(dirname + "\\Cache\\*.*")
        for srumfile in srum_files:
            os.chmod(srumfile, stat.S_IWRITE)
            os.remove(srumfile)

        srum_files = glob.glob(dirname + SrumDir + "\\*.*")
        for srumfile in srum_files:
            shutil.copy(srumfile, dirname + "\\Cache\\")

        shutil.copy( dirname + SysRegs + "\\SOFTWARE", dirname + "\\Cache\\")

        srum_files = glob.glob(dirname + "\\Cache\\*.*")
        for srumfile in srum_files:
            os.chmod(srumfile, stat.S_IWRITE)

    ###########################################################################
    # Fell Through, Now Process the files and extract data for report
    ###########################################################################
    if len(PreConv) > 1:
        print("[+] Now Running Pre-Conversion Script: " + PreConv)
        cmdexec = PreConv + " " + dirname
        returned_value = os.system(cmdexec)


    ###########################################################################
    # Fell Through, Now Process the files and extract data for report         #
    ###########################################################################
    print("[+] Now Processing AChoir Extraction: " + dirname)


    ###########################################################################
    # Create System Information Timesketch CSV                                #
    ###########################################################################
    filnout = dirtrge + "\\ts_system.csv"
    csvoutf = open(filnout, "w", encoding='utf8', errors="replace")
    csvoutf.write("\"datetime\",\"message\",\"timestamp_desc\",\"data_type\"\n")
    csvoutf.write("\"" + datetime.datetime.now(datetime.timezone.utc).isoformat() + "\",\"Initial Timesketch Load\",\"autorun_date\",\"system:runtime\"\n")
    csvoutf.close()


    ###########################################################################
    # Parse Prefetch Files                                                    #
    ###########################################################################
    if RunAllAll == 1 or SrcPrf == 1:
        print("[+] Generating Prefetch Data...")
        exeName = dirleft + "\\SYS\\WinPrefetchView.exe"

        if os.path.isfile(exeName):
            if os.path.isdir(dirname + Prefetc):
                cmdexec = dirleft + "\\SYS\\WinPrefetchView.exe /folder " + dirname + Prefetc + " /scomma  " + dirtrge + "\\WinPrefetchview.csv"
                returned_value = os.system(cmdexec)
            else:
                print("[!] Prefetch Data Not Found in the Collection: " + dirname + Prefetc)
                SrcPrf = 0
        else:
            print("[!] WinPrefetchView Not Found...")
            SrcPrf = 0

        ###########################################################################
        # Transform Prefetch CSV for Timesketch                                    #
        ###########################################################################
        reccount = 0
        filname = dirtrge + "\\WinPrefetchview.csv"
        filnout = dirtrge + "\\ts_prefetchview.csv"

        if os.path.isfile(filname):
            csvoutf = open(filnout, "w", encoding='utf8', errors="replace")
            with open(filname, 'r', encoding='utf8', errors="replace") as csvfile:
                csvread = csv.reader((line.replace('\0','') for line in csvfile), delimiter=',')
                for csvrow in csvread:
                    if len(csvrow) > 8:
                        if reccount == 0:
                            ###########################################################################
                            # Write out a header                                                      #
                            ###########################################################################
                            csvoutf.write("\"filename\",\"created_time\",\"modified_time\",\"file_size\",\"Process_exe\",\"process_path\",\"run_count\",\"last_run\",\"missing_process\","
                                        + "\"message\",\"datetime\",\"timestamp_desc\",\"data_type\"\n")

                        if csvrow[0] == "":
                            csvrow[0] = "1900-01-01T19:01:01"
                        else:
                            datetime_object = datetime.datetime.strptime(csvrow[2], "%m/%d/%Y %I:%M:%S %p")
                            iso_string = datetime_object.isoformat()

                        csvoutf.write("\"" 
                                     + csvrow[0].replace(',',' - ').replace('"','') + "\",\"" + csvrow[1].replace(',',' - ').replace('"','') + "\",\"" 
                                     + csvrow[2].replace(',',' - ').replace('"','') + "\",\"" + csvrow[3].replace(',',' - ').replace('"','') + "\",\"" 
                                     + csvrow[4].replace(',',' - ').replace('"','') + "\",\"" + csvrow[5].replace(',',' - ').replace('"','') + "\",\"" 
                                     + csvrow[6].replace(',',' - ').replace('"','') + "\",\"" + csvrow[7].replace(',',' - ').replace('"','') + "\",\""
                                     + csvrow[8].replace(',',' - ').replace('"','') + "\",\"" + csvrow[0].replace(',',' - ').replace('"','') + " - "
                                     + csvrow[5].replace(',',' - ').replace('"','') + "\",\"" + iso_string + "\",\"" 
                                     + "prefetch_lastmod\",\"prefetch:lastmod\"\n")

                        reccount = reccount + 1

            if reccount < 2:
                print("[!] No Records Processed: " + dirname)
                csvoutf.write("\"NoData\",\"NoData\",\"NoData\",\"NoData\",\"NoData\",\"NoData\",\"NoData\",\"NoData\",\"NoData\","
                             + "\"No Data Parsed From Input\",\"1900-01-01T19:01:01\",\"NoData\",\"NoData:Input\"\n")
            else:
                print("[+] Records Processed: " + str(reccount))

            csvfile.close()
            csvoutf.close()

        else:
            print("[!] BBypassing Prefetch Data ...")
    else:
        print("[!] Bypassing Prefetch Data ...")


    ###########################################################################
    # Write AutoRuns (Use Python CSV Reader Module)                           #
    ###########################################################################
    if RunAllAll == 1 or RunAutoRn == 1:
        print("[+] Transforming Autoruns Information...")

        reccount = 0
        filname = dirname + AutoRun
        filnout = dirtrge + "\\ts_autoruns.csv"

        if os.path.isfile(filname):
            csvoutf = open(filnout, "w", encoding='utf8', errors="replace")
            with open(filname, 'r', encoding='utf8', errors="replace") as csvfile:
                csvread = csv.reader((line.replace('\0','') for line in csvfile), delimiter=',')
                for csvrow in csvread:
                    if len(csvrow) > 15:
                        if reccount == 0:
                            csvoutf.write("\"datetime\",\"" 
                                         + csvrow[1].replace(',',' - ').replace('"','') + "\",\"" + csvrow[2].replace(',',' - ').replace('"','') + "\",\"" 
                                         + csvrow[3].replace(',',' - ').replace('"','') + "\",\"" + csvrow[4].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[5].replace(',',' - ').replace('"','') + "\",\"" + "message" +"\",\"" + csvrow[7].replace(',',' - ').replace('"','') +"\",\""
                                         + csvrow[8].replace(',',' - ').replace('"','') + "\",\"" + csvrow[9].replace(',',' - ').replace('"','') + "\",\"" 
                                         + csvrow[10].replace(',',' - ').replace('"','') + "\",\"" + csvrow[11].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[12].replace(',',' - ').replace('"','') + "\",\"" + csvrow[13].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[14].replace(',',' - ').replace('"','') + "\",\"" + csvrow[15].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[16].replace(',',' - ').replace('"','') + "\",\"" + "timestamp_desc\",\"data_type\"\n")
                        else:
                            if csvrow[0] == "":
                                csvrow[0] = "1900-01-01T19:01:01"
                            else:
                                datetime_object = datetime.datetime.strptime(csvrow[0], "%m/%d/%Y %I:%M %p")
                                iso_string = datetime_object.isoformat()

                            csvoutf.write("\"" + iso_string + "\",\""
                                         + csvrow[1].replace(',',' - ').replace('"','') + "\",\"" + csvrow[2].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[3].replace(',',' - ').replace('"','')  + "\",\"" + csvrow[4].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[5].replace(',',' - ').replace('"','') + "\",\"" + csvrow[6].replace(',',' - ').replace('"','') + " - " 
                                         + csvrow[10].replace(',',' - ').replace('"','') + "\",\"" + csvrow[7].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[8].replace(',',' - ').replace('"','') + "\",\"" + csvrow[9].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[10].replace(',',' - ').replace('"','') + "\",\"" + csvrow[11].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[12].replace(',',' - ').replace('"','') + "\",\"" + csvrow[13].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[14].replace(',',' - ').replace('"','') +"\",\"" + csvrow[15].replace(',',' - ').replace('"','') +"\",\""
                                         + csvrow[16].replace(',',' - ').replace('"','') + "\",\""
                                         + "autorun_date\",\"autoruns:autorun\"\n")

                        reccount = reccount + 1

            if reccount < 2:
                print("[!] No Records Processed: " + dirname)
                csvoutf.write("\"1900-01-01T19:01:01\",\"" 
                             + "NoData" + "\",\"" + "NoData" + "\",\"" 
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "No Data Parsed From Input" +"\",\"" + "NoData" +"\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\"" 
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData\",\"NoData:Input\"\n")
            else:
                print("[+] Records Processed: " + str(reccount))

            csvfile.close()
            csvoutf.close()

        else:
            print("[!] Bypassing Browser History Transform (No Input Data) ...")
    else:
        print("[!] Bypassing Browser History Transform (No Input Data) ...")


    ###########################################################################
    # Parse Desktop and Recent Link Files                                     #
    ###########################################################################
    if RunAllAll == 1 or RunLnkPrs == 1:
        print("[+] Generating Desktop and Recent LNK Information...")

        print("[+] Checking for Eric Zimmerman LECmd Link Parser...")

        exeName = ".\\LECmd.exe"
        if os.path.isfile(exeName):
            print("[+] LECmd executable found")
            print("[+] Parsing Desktop and Recent LNK Files from Multiple User Profiles...")

            curdir = dirname + LNKFile
            filname = "LNKFiles.csv"
            fulname = dirtrge + "\\" + filname
            cmdexec = exeName + " -q -d " + curdir + " --dt \"yyyy-MM-dd HH:mm:ss K\" --csv " + dirtrge + " --csvf " + filname 
            returned_value = os.system(cmdexec)

            print("[+] Reading Desktop and Recent LNK Files from Multiple User Profiles...")

            reccount = 0
            filname = dirtrge + "\\" + filname
            filnout = dirtrge + "\\ts_lnkfiles.csv"

        if os.path.isfile(filname):
            csvoutf = open(filnout, "w", encoding='utf8', errors="replace")
            with open(filname, 'r', encoding='utf8', errors="replace") as csvfile:
                csvread = csv.reader((line.replace('\0','') for line in csvfile), delimiter=',')
                for csvrow in csvread:
                    if len(csvrow) > 25:
                        if reccount == 0:
                            csvoutf.write("\"message\",\"" + csvrow[0].replace(',',' - ').replace('"','') + "\",\"" + csvrow[1].replace(',',' - ').replace('"','') + "\",\"" 
                                         + csvrow[2].replace(',',' - ').replace('"','') + "\",\"" + csvrow[3].replace(',',' - ').replace('"','') + "\",\"" 
                                         + csvrow[4].replace(',',' - ').replace('"','') + "\",\"" + csvrow[5].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[6].replace(',',' - ').replace('"','') + "\",\"" + csvrow[7].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[8].replace(',',' - ').replace('"','') + "\",\"" + csvrow[9].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[10].replace(',',' - ').replace('"','') + "\",\"" + csvrow[11].replace(',',' - ').replace('"','') + "\",\"" 
                                         + csvrow[12].replace(',',' - ').replace('"','') + "\",\"" + csvrow[13].replace(',',' - ').replace('"','') + "\",\"" 
                                         + csvrow[14].replace(',',' - ').replace('"','') + "\",\"" + csvrow[15].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[16].replace(',',' - ').replace('"','') + "\",\"" + csvrow[17].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[18].replace(',',' - ').replace('"','') + "\",\"" + csvrow[19].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[20].replace(',',' - ').replace('"','') + "\",\"" + csvrow[21].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[22].replace(',',' - ').replace('"','') + "\",\"" + csvrow[23].replace(',',' - ').replace('"','') + "\",\"" 
                                         + csvrow[24].replace(',',' - ').replace('"','') + "\",\"" + csvrow[25].replace(',',' - ').replace('"','') + "\",\""
                                          + "datetime\",\"timestamp_desc\",\"data_type\"\n")
                        else:
                            csvoutf.write("\"" + csvrow[0].replace(',',' - ').replace('"','') + "\",\"" + csvrow[0].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[1].replace(',',' - ').replace('"','') + "\",\"" + csvrow[2].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[3].replace(',',' - ').replace('"','') + "\",\"" + csvrow[4].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[5].replace(',',' - ').replace('"','') + "\",\"" + csvrow[6].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[7].replace(',',' - ').replace('"','') + "\",\"" + csvrow[8].replace(',',' - ').replace('"','') + "\",\"" 
                                         + csvrow[9].replace(',',' - ').replace('"','') + "\",\"" + csvrow[10].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[11].replace(',',' - ').replace('"','') + "\",\"" + csvrow[12].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[13].replace(',',' - ').replace('"','') + "\",\"" + csvrow[14].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[15].replace(',',' - ').replace('"','') + "\",\"" + csvrow[16].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[17].replace(',',' - ').replace('"','') + "\",\"" + csvrow[18].replace(',',' - ').replace('"','') + "\",\"" 
                                         + csvrow[19].replace(',',' - ').replace('"','') + "\",\"" + csvrow[20].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[21].replace(',',' - ').replace('"','') + "\",\"" + csvrow[22].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[23].replace(',',' - ').replace('"','') + "\",\"" + csvrow[24].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[25].replace(',',' - ').replace('"','') + "\",\"" + csvrow[2].replace(',',' - ').replace('"','') + "\",\""
                                         + "timestamp_desc\",\"data_type\"\n")

                        reccount = reccount + 1


            if reccount < 2:
                print("[!] No Records Processed: " + dirname)
                csvoutf.write("\"No Data Parsed From Input\",\"" + "NoData" + "\",\"" + "NoData" + "\",\"" 
                             + "NoData" + "\",\"" + "NoData" + "\",\"" 
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\"" 
                             + "NoData" + "\",\"" + "NoData" + "\",\"" 
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\"" 
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "1900-01-01T19:01:01\",\"NoData\",\"NoData:Input\"\n")
            else:
                print("[+] Records Processed: " + str(reccount))

            csvfile.close()
            csvoutf.close()

        else:
            print("[!] Bypassing Link File Transform (No Input Data) ...")
    else:
        print("[!] Bypassing Link File Transform (No Input Data) ...")


    ###########################################################################
    # Write LastActivityView Data (Use Python CSV Reader Module)              #
    ###########################################################################
    if RunAllAll == 1 or RunLastAct == 1:
        print("[+] Transforming Last Activity View Information...")

        reccount = 0
        filname = dirname + LastAct
        filnout = dirtrge + "\\ts_lastact.csv"

        if os.path.isfile(filname):
            csvoutf = open(filnout, "w", encoding='utf8', errors="replace")
            with open(filname, 'r', encoding='utf8', errors="replace") as csvfile:
                csvread = csv.reader((line.replace('\0','') for line in csvfile), delimiter=',')
                for csvrow in csvread:
                    if len(csvrow) > 5:
                        if reccount == 0:
                            csvoutf.write("\"datetime\",\""
                                         + csvrow[1].replace(',',' - ').replace('"','') + "\",\"" + csvrow[2].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[3].replace(',',' - ').replace('"','') + "\",\"" + csvrow[4].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[5].replace(',',' - ').replace('"','') + "\",\"" + csvrow[6].replace(',',' - ').replace('"','') + "\",\""
                                         + "message\",\"timestamp_desc\",\"data_type\"\n")
                        else:
                            datetime_object = datetime.datetime.strptime(csvrow[0].replace(',',' - ').replace('"',''), "%m/%d/%Y %I:%M:%S %p")
                            iso_string = datetime_object.isoformat()

                            if len(csvrow[4]) < 1:
                                MoreInfo = ""
                            else:
                                MoreInfo = " - MoreInfo: "

                            csvoutf.write("\"" + iso_string + "\",\""
                                         + csvrow[1].replace(',',' - ').replace('"','') + "\",\"" + csvrow[2].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[3].replace(',',' - ').replace('"','') + "\",\"" + csvrow[4].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[5].replace(',',' - ').replace('"','') + "\",\"" + csvrow[6].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[1].replace(',',' - ').replace('"','') + " - Path: " + csvrow[3].replace(',',' - ').replace('"','')
                                         + MoreInfo + csvrow[4].replace(',',' - ').replace('"','') + "\",\""
                                         + "LastActivty\",\"Activity:last\"\n")

                        reccount = reccount + 1

            if reccount < 2:
                print("[!] No Records Processed: " + dirname)
                csvoutf.write("\"1900-01-01T19:01:01\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "No Data Parsed From Input\",\"NoData\",\"NoData:Input\"\n")
            else:
                print("[+] Records Processed: " + str(reccount))

            csvfile.close()
            csvoutf.close()

        else:
            print("[!] Bypassing Last Activity View Transform (No Input Data) ...")
    else:
        print("[!] Bypassing Last Activity View Transform (No Input Data) ...")


    ###########################################################################
    # Write Web Browser Data (Use Python CSV Reader Module)                   #
    ###########################################################################
    if RunAllAll == 1 or RunFBrHst == 1:
        print("[+] Transforming File and Web Browser Information...")

        reccount = 0
        filname = dirname + Browser
        filnout = dirtrge + "\\ts_browsehist.csv"

        if os.path.isfile(filname):
            csvoutf = open(filnout, "w", encoding='utf8', errors="replace")
            with open(filname, 'r', encoding='utf8', errors="replace") as csvfile:
                csvread = csv.reader((line.replace('\0','') for line in csvfile), delimiter=',')
                for csvrow in csvread:
                    if len(csvrow) > 13:
                        if reccount == 0:
                            csvoutf.write("\"message\",\""
                                         + csvrow[1].replace(',',' - ').replace('"','') + "\",\"" + csvrow[2].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[3].replace(',',' - ').replace('"','') + "\",\"" + csvrow[4].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[5].replace(',',' - ').replace('"','') + "\",\"" + csvrow[6].replace(',',' - ').replace('"','') +"\",\""
                                         + csvrow[7].replace(',',' - ').replace('"','') +  "\",\"" + csvrow[8].replace(',',' - ').replace('"','')  + "\",\""
                                         + csvrow[9].replace(',',' - ').replace('"','') + "\",\"" + csvrow[10].replace(',',' - ').replace('"','') +"\",\""
                                         + csvrow[11].replace(',',' - ').replace('"','') +"\",\"" + csvrow[12].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[13].replace(',',' - ').replace('"','') + "\",\""
                                         + "datetime\",\"timestamp_desc\",\"data_type\"\n")
                        else:
                            datetime_object = datetime.datetime.strptime(csvrow[2].replace(',',' - ').replace('"',''), "%m/%d/%Y %I:%M:%S %p")
                            iso_string = datetime_object.isoformat()
                            if csvrow[0].startswith("file:///"):
                                csvoutf.write("\""
                                             + csvrow[0].replace(',',' - ').replace('"','') + "\",\"" + csvrow[1].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[2].replace(',',' - ').replace('"','') + "\",\"" + csvrow[3].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[4].replace(',',' - ').replace('"','') + "\",\"" + csvrow[5].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[6].replace(',',' - ').replace('"','') + "\",\"" + csvrow[7].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[8].replace(',',' - ').replace('"','') + "\",\"" + csvrow[9].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[10].replace(',',' - ').replace('"','') + "\",\"" + csvrow[11].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[12].replace(',',' - ').replace('"','') + "\",\"" + csvrow[13].replace(',',' - ').replace('"','') + "\",\""
                                             + iso_string + "\",\"" + "fileOpen\",\"browser:file\"\n")
                            else:
                                csvoutf.write("\""
                                             + csvrow[0].replace(',',' - ').replace('"','') + "\",\"" + csvrow[1].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[2].replace(',',' - ').replace('"','') + "\",\"" + csvrow[3].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[4].replace(',',' - ').replace('"','') + "\",\"" + csvrow[5].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[6].replace(',',' - ').replace('"','') + "\",\"" + csvrow[7].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[8].replace(',',' - ').replace('"','') + "\",\"" + csvrow[9].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[10].replace(',',' - ').replace('"','') + "\",\"" + csvrow[11].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[12].replace(',',' - ').replace('"','') + "\",\"" + csvrow[13].replace(',',' - ').replace('"','') + "\",\""
                                             + iso_string + "\",\"" + "websiteVisit\",\"browser:visit\"\n")

                        reccount = reccount + 1

            if reccount < 2:
                print("[!] No Records Processed: " + dirname)
                csvoutf.write("\"No Data Parsed From Input\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\""
                             + "1900-01-01T19:01:01\",\"NoData\",\"NoData:Input\"\n")
            else:
                print("[+] Records Processed: " + str(reccount))

            csvfile.close()
            csvoutf.close()

        else:
            print("[!] Bypassing Browser History Transform (No Input Data) ...")
    else:
        print("[!] Bypassing Browser History Transform (No Input Data) ...")



    ###########################################################################
    # Write Web Browser Downloads (Use Python CSV Reader Module)              #
    ###########################################################################
    if RunAllAll == 1 or RunFBrHst == 1:
        print("[+] Transforming File and Web Browser Downloads...")

        reccount = 0
        filname = dirname + Downlod
        filnout = dirtrge + "\\ts_browsedown.csv"

        if os.path.isfile(filname):
            csvoutf = open(filnout, "w", encoding='utf8', errors="replace")
            with open(filname, 'r', encoding='utf8', errors="replace") as csvfile:
                csvread = csv.reader((line.replace('\0','') for line in csvfile), delimiter=',')
                for csvrow in csvread:
                    if len(csvrow) > 18:
                        if reccount == 0:
                            csvoutf.write("\""
                                         + csvrow[0].replace(',',' - ').replace('"','') + "\",\"" + "message" + "\",\"" + csvrow[2].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[3].replace(',',' - ').replace('"','') + "\",\"" + csvrow[4].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[5].replace(',',' - ').replace('"','') + "\",\"" + csvrow[6].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[7].replace(',',' - ').replace('"','') + "\",\"" + csvrow[8].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[9].replace(',',' - ').replace('"','') + "\",\"" + csvrow[10].replace(',',' - ').replace('"','') +"\",\""
                                         + csvrow[11].replace(',',' - ').replace('"','') +"\",\"" + csvrow[12].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[13].replace(',',' - ').replace('"','') + "\",\"" + csvrow[14].replace(',',' - ').replace('"','') +"\",\""
                                         + csvrow[15].replace(',',' - ').replace('"','') + "\",\"" + csvrow[16].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[17].replace(',',' - ').replace('"','') + "\",\"" + csvrow[18].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[19].replace(',',' - ').replace('"','') + "\",\""
                                         + "datetime\",\"timestamp_desc\",\"data_type\"\n")
                        else:
                            datetime_object = datetime.datetime.strptime(csvrow[5].replace(',', ' - '), "%m/%d/%Y %I:%M:%S %p")
                            iso_string = datetime_object.isoformat()
                            csvoutf.write("\""
                                         + csvrow[0].replace(',',' - ').replace('"','') + "\",\"" + csvrow[1].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[2].replace(',',' - ').replace('"','') + "\",\"" + csvrow[3].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[4].replace(',',' - ').replace('"','') + "\",\"" + csvrow[5].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[6].replace(',',' - ').replace('"','') + "\",\"" + csvrow[7].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[8].replace(',',' - ').replace('"','') + "\",\"" + csvrow[9].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[10].replace(',',' - ').replace('"','') + "\",\"" + csvrow[11].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[12].replace(',',' - ').replace('"','') + "\",\"" + csvrow[13].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[14].replace(',',' - ').replace('"','') + "\",\"" + csvrow[15].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[16].replace(',',' - ').replace('"','') + "\",\"" + csvrow[17].replace(',',' - ').replace('"','') + "\",\""
                                         + csvrow[18].replace(',',' - ').replace('"','') + "\",\"" + csvrow[19].replace(',',' - ').replace('"','') + "\",\""
                                         + iso_string + "\",\"" + "webDownload\",\"browser:download\"\n")

                        reccount = reccount + 1

            if reccount < 2:
                print("[!] No Records Processed: " + dirname)
                csvoutf.write("\""
                             + "NoData" + "\",\"" + "No Data parsed From Input" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\"" + "NoData" + "\",\""
                             + "NoData" + "\",\""
                             + "1900-01-01T19:01:01\",\"NoData\",\"NoData:Input\"\n")
            else:
                print("[+] Records Processed: " + str(reccount))

            csvfile.close()
            csvoutf.close()

        else:
            print("[!] Bypassing Browser History Transform (No Input Data) ...")
    else:
        print("[!] Bypassing Browser History Transform (No Input Data) ...")


    ###########################################################################
    # Parse SRUM DB                                                           #
    ###########################################################################
    if RunAllAll == 1 or SrcSrum == 1:
        print("[+] Generating SRUM Data...")
        exeName = dirleft + "\\SYS\\SrumECmd.exe"

        if os.path.isfile(exeName):
            if os.path.isdir(dirname + SrumDir) and os.path.isfile(dirname + SysRegs + "\\SOFTWARE"):
                cmdexec = dirleft + "\\SYS\\SrumECmd.exe -d " + dirname + "\\Cache -r " + dirname + "\\Cache\\SOFTWARE --csv " + dirtrge + "\\SRUM"
                returned_value = os.system(cmdexec)

                ###########################################################################
                # Transform Just the Network activity for Timesketch                      #
                ###########################################################################
                
                for curfile in os.listdir(dirtrge + "\\SRUM"):
                    if curfile.endswith("SrumECmd_NetworkUsages_Output.csv"):
                        reccount = 0
                        filname = dirtrge + "\\SRUM\\" + curfile
                        filnout = dirtrge + "\\ts_srumnetusage.csv"

                        csvoutf = open(filnout, "w", encoding='utf8', errors="replace")
                        with open(filname, 'r', encoding='utf8', errors="replace") as csvfile:
                            csvread = csv.reader((line.replace('\0','') for line in csvfile), delimiter=',')
                            for csvrow in csvread:
                                if len(csvrow) > 15:
                                    if reccount == 0:
                                        csvoutf.write("\""
                                                     + csvrow[0].replace(',',' - ').replace('"','') + "\",\"" + "datetime" + "\",\"" + "message" + "\",\""
                                                     + csvrow[3].replace(',',' - ').replace('"','') + "\",\"" + csvrow[4].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[5].replace(',',' - ').replace('"','') + "\",\"" + csvrow[6].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[7].replace(',',' - ').replace('"','') + "\",\"" + csvrow[8].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[9].replace(',',' - ').replace('"','') + "\",\"" + csvrow[10].replace(',',' - ').replace('"','') +"\",\""
                                                     + csvrow[11].replace(',',' - ').replace('"','') +"\",\"" + csvrow[12].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[13].replace(',',' - ').replace('"','') + "\",\"" + csvrow[14].replace(',',' - ').replace('"','') +"\",\""
                                                     + csvrow[15].replace(',',' - ').replace('"','') + "\",\"" + csvrow[16].replace(',',' - ').replace('"','') + "\",\""
                                                     + "timestamp_desc\",\"data_type\"\n")
                                    else:
                                        csvoutf.write("\""
                                                     + csvrow[0].replace(',',' - ').replace('"','') + "\",\"" + csvrow[1].replace(' ', 'T').replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[2].replace(',',' - ').replace('"','') + " - Bytes In: " +  csvrow[10].replace(',',' - ').replace('"','')
                                                     + " - Bytes Out: " + csvrow[11].replace(',',' - ').replace('"','') + "\",\"" + csvrow[3].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[4].replace(',',' - ').replace('"','') + "\",\"" + csvrow[5].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[6].replace(',',' - ').replace('"','') + "\",\"" + csvrow[7].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[8].replace(',',' - ').replace('"','') + "\",\"" + csvrow[9].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[10].replace(',',' - ').replace('"','') + "\",\"" + csvrow[11].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[12].replace(',',' - ').replace('"','') + "\",\"" + csvrow[13].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[14].replace(',',' - ').replace('"','') + "\",\"" + csvrow[15].replace(',',' - ').replace('"','') + "\",\""
                                                     + csvrow[16].replace(',',' - ').replace('"','') + "\",\""
                                                     + "srumnetusage\",\"srum:netusage\"\n")

                                    reccount = reccount + 1

                        if reccount < 2:
                            print("[!] No Records Processed: " + dirname)
                            csvoutf.write("\""
                                         + "NoData" + "\",\"" + "1900-01-01T19:01:01" + "\",\"" + "No Data Parsed From Input" + "\",\""
                                         + "NoData" + "\",\"" + "NoData" + "\",\""
                                         + "NoData" + "\",\"" + "NoData" + "\",\""
                                         + "NoData" + "\",\"" + "NoData" + "\",\""
                                         + "NoData" + "\",\"" + "NoData" + "\",\""
                                         + "NoData" + "\",\"" + "NoData" + "\",\""
                                         + "NoData" + "\",\"" + "NoData" + "\",\""
                                         + "NoData" + "\",\"" + "NoData" + "\",\""
                                         + "NoData\",\"NoData:Input\"\n")
                        else:
                            print("[+] Records Processed: " + str(reccount))

                        csvfile.close()
                        csvoutf.close()

            else:
                print("[!] SRUM or SYSTEM registry Not Found in the Collection: " + dirname + SrumDir)
                SrcPrf = 0
        else:
            print("[!] SrumECmd Not Found...")
            SrcPrf = 0
    else:
        print("[!] Bypassing SRUM Data ...")


    ###########################################################################
    # Run Countercept Chainsaw Program against all .EVTX Files                #
    #                                                                         #
    # IMPORTANT NOTE: This section is coded for Chainsaw v2.9 - Other         #
    #  versions may require modifications to accomodate, since output can     #
    #  change between versions.                                               #
    ###########################################################################
    if (RunAllAll == 1 or RunChnSaw == 1) and SrcEvtx == 1:
        print("[+] Checking for F-Secure Countercept Chainsaw...")

        filnout = dirtrge + "\\ts_chainsaw.csv"

        if os.path.isfile(".\\chainsaw\\chainsaw_x86_64-pc-windows-msvc.exe") == False:
            print("[?] Chainsaw executable not found...  Would you like to Download F-Secure Countercept...")
            YesOrNo = "Y"
            try:
                YesOrNo = input("[?] Y/N > ")
            except EOFError:
                YesOrnNo = "Y"

            if YesOrNo.upper() == "Y":
                print("[+] Downloading F-Secure Countercept Chainsaw From Github...")
                ChSwUrl = 'https://github.com/WithSecureLabs/chainsaw/releases/download/v2.9.0/chainsaw_all_platforms+rules+examples.zip'
                ChSwReq = requests.get(ChSwUrl, allow_redirects=True)
                open('Chainsaw.zip', 'wb').write(ChSwReq.content)

                print("[+] Unzipping F-Secure Countercept Chainsaw...")
                with ZipFile('Chainsaw.zip', 'r') as zipObj:
                    # Extract all the contents of zip file in current directory
                    zipObj.extractall()
            else:
                print("[!] Chainsaw Download Bypassed...")


        if os.path.isfile(".\\chainsaw\\chainsaw_x86_64-pc-windows-msvc.exe"):
            csvoutf = open(filnout, "w", encoding='utf8', errors="replace")

            print("[+] Chainsaw executable found")
            print("[+] Running F-Secure Countercept Chainsaw against all Event Logs...")

            ChSwSubDir = ""

            EvtName = dirname + EvtDir1
            cmdexec = ".\\chainsaw\\chainsaw_x86_64-pc-windows-msvc.exe hunt " + " --skip-errors --timezone UTC --full --csv --output " + dirtrge + "\\ChainCSV --mapping .\\chainsaw\\mappings\\sigma-event-logs-all.yml --rule .\\chainsaw\\rules --sigma .\\chainsaw\\sigma " + EvtName
            returned_value = os.system(cmdexec)

            ###########################################################################
            # Chainsaw: Log Tampering - Implement in Next Version                     #
            ###########################################################################
            ###########################################################################
            # Chainsaw: Account Tampering - Implement in Next Version                 #
            ###########################################################################
            ###########################################################################
            # Chainsaw: Login Attacks - Implement in Next Version                     #
            ###########################################################################
            ###########################################################################
            # Chainsaw: Antivirus Detections - Implement in Next Version              #
            ###########################################################################
            ###########################################################################
            # Chainsaw: Lateral Movement - Implement in Next Version                  #
            ###########################################################################
            ###########################################################################
            # Chainsaw: Log Tampering (v1.45) - Implement in Next Version             #
            ###########################################################################
            ###########################################################################
            # Chainsaw: Powershell Script (v1.45) - Implement in Next Version         #
            ###########################################################################
            ###########################################################################
            # Chainsaw: RDP Attacks (v1.45) - Implement in Next Version               #
            ###########################################################################
            ###########################################################################
            # Chainsaw: RDP Events (v1.45) - Implement in Next Version                #
            ###########################################################################
            ###########################################################################
            # Chainsaw: Service Installation (v1.45) - Implement in Next Version      #
            ###########################################################################
            ###########################################################################
            # Chainsaw: Sigma Detections                                              #
            ###########################################################################
            for ChName in glob.glob(dirtrge + '\\**\\sigma.csv', recursive=True):
                reccount = 0
                with open(ChName, 'r', encoding='utf8', errors="replace") as csvfile:
                    csvread = csv.reader((line.replace('\0','') for line in csvfile), delimiter=',')
                    for csvrow in csvread:
                        if len(csvrow) > 8:
                            if reccount == 0:
                                csvoutf.write("\"" + "datetime" + "\",\"" + "message" + "\",\""
                                             + csvrow[2].replace(',',' - ').replace('"','') + "\",\"" + csvrow[3].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[4].replace(',',' - ').replace('"','') + "\",\"" + csvrow[5].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[6].replace(',',' - ').replace('"','') + "\",\"" + csvrow[7].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[8].replace(',',' - ').replace('"','') + "\",\""
                                             + "timestamp_desc\",\"data_type\"\n")
                            else:
                                ###########################################################################
                                # Sigma Rules - Sanity check detection start                              #
                                ###########################################################################
                                if "defender" in csvrow[1].replace(',',' - ').lower() and "defender" not in csvrow[3].replace(',',' - ').lower():
                                    continue

                                if "sysmon" in csvrow[1].replace(',', ' - ').lower() and "sysmon" not in csvrow[3].replace(',', ' - ').lower():
                                    continue

                                if "file was not allowed to run" in csvrow[1].replace(',', ' - ').lower() and "applocker" not in csvrow[3].replace(',', ' - ').lower():
                                    continue

                                csvrow[0].replace(" ", "T")
                                csvoutf.write("\""
                                             + csvrow[0].replace(',',' - ').replace('"','') + "\",\"" + csvrow[1].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[2].replace(',',' - ').replace('"','') + "\",\"" + csvrow[3].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[4].replace(',',' - ').replace('"','') + "\",\"" + csvrow[5].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[6].replace(',',' - ').replace('"','') + "\",\"" + csvrow[7].replace(',',' - ').replace('"','') + "\",\""
                                             + csvrow[8].replace(',',' - ').replace('"','') + "\",\""
                                             + "chainsaw_sigma\",\"chainsaw:sigma\"\n")


                        reccount = reccount + 1

                if reccount < 2:
                    print("[!] No Records Processed: " + dirname)
                    csvoutf.write("\"" + "1900-01-01T19:01:01" + "\",\"" + "No Data Parsed From Input" + "\",\""
                                 + "NoData" + "\",\"" + "NoData" + "\",\""
                                 + "NoData" + "\",\"" + "NoData" + "\",\""
                                 + "NoData" + "\",\"" + "NoData" + "\",\""
                                 + "NoData" + "\",\""
                                 + "NoData\",\"NoData:Input\"\n")
                else:
                    print("[+] Records Processed: " + str(reccount))

                csvfile.close()
                csvoutf.close()

        else:
            print("[!] Chainsaw Executable not found!  Bypassing Chainsaw Processing...")

    else:
        print("[!] Bypassing Chainsaw Processing...")


    ###########################################################################
    # Run Yamato-Security/hayabusa against all .EVTX Files                    #
    #                                                                         #
    # IMPORTANT NOTE: This section is coded for Chainsaw v2.15.0 - Other      #
    #  versions may require modifications to accomodate, since output can     #
    #  change between versions.                                               #
    ###########################################################################
    if (RunAllAll == 1 or RunChnSaw == 1) and SrcEvtx == 1:
        print("[+] Checking for Yamato-Security/hayabusa...")

        if os.path.isfile(".\\hayabusa\\hayabusa-2.15.0-win-x64.exe") == False:
            print("[?] Hayabusa executable not found...  Would you like to Download hayabusa 2.15.0...")
            YesOrNo = "Y"

            try:
                YesOrNo = input("[?] Y/N > ")
            except EOFError:
                YesOrnNo = "Y"

            if YesOrNo.upper() == "Y":
                print("[+] Downloading hayabusa 2.15.0 From Github...")
                ChSwUrl = 'https://github.com/Yamato-Security/hayabusa/releases/download/v2.15.0/hayabusa-2.15.0-win-x64.zip'
                ChSwReq = requests.get(ChSwUrl, allow_redirects=True)
                open('Hayabusa.zip', 'wb').write(ChSwReq.content)

                print("[+] Unzipping Hayabusa...")
                with ZipFile('Hayabusa.zip', 'r') as zipObj:
                    # Extract all the contents of zip file in current directory
                    zipObj.extractall(path=".\\hayabusa")
            else:
                print("[!] Hayabusa Download Bypassed...")


        ###########################################################################
        # Hayabusa: Writes CSV in Timesketch format - not need for Transform      #
        ###########################################################################
        if os.path.isfile(".\\hayabusa\\hayabusa-2.15.0-win-x64.exe"):
            print("[+] Hayabusa executable found")
            print("[+] Running Hayabusa against all Event Logs...")

            ChSwSubDir = ""
            EvtName = dirname + EvtDir1
            returned_value = os.system("mkdir " + dirtrge + "\\Hayabusa")
            cmdexec = ".\\hayabusa\\hayabusa-2.15.0-win-x64.exe csv-timeline -w --UTC -d " + EvtName + " -o " + dirtrge + "\\Hayabusa\\ts_Hayabusa.csv -p timesketch-verbose --ISO-8601"
            returned_value = os.system(cmdexec)

            # Old version uses OS Copy
            # cmdexec = "copy " + dirtrge + "\\Hayabusa\\ts_Hayabusa.csv " + dirtrge + "\\"
            # returned_value = os.system(cmdexec)

            # New Version used Python shutil
            shutil.copy(dirtrge + "\\Hayabusa\\ts_Hayabusa.csv", dirtrge + "\\")

        else:
            print("[!] Hayabusa Executable not found!  Bypassing Hayabusa Processing...")

    else:
        print("[!] Bypassing Hayabusa Processing...")

    print("[+] Transform Processing Complete!\n")


if __name__ == "__main__":
    main()
