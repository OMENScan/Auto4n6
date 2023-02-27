# Auto4n6 (v0.01)
Auto4n6 is a set of 
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a>
Scripts coupled with several other Open Source forensics programs that automate the parsing and reporting of both Memory dumps and Forensic Triage collections.

Auto4n6 currently requires quite a bit of customised configuration to identify how a triage collection should be parsed.  This is necessary to get a working version of the tool into a working Proof of Concept.  Right now "it works on my machine".  Future versions will focus on better ways to determine how to parse and process collection data with far less configuration, to make it flexible enough to work with more data sources and require less modification.  I'm just getting started!

# Purpose
Automation of forensic collection and processing has always been my goal.  It started with 
<a href=https://github.com/OMENScan/AChoir> AChoir </a> and 
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a>, 
which are designed to make forensic collection (live response or 
<a href=https://github.com/OMENScan/AChoirX/tree/master/ToolsBuiltWithAChoirX/AChDBox> dead-box</a>) 
consistent and reliable. I designed 
<a href=https://github.com/OMENScan/AChoir> AChoir </a> and 
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a>
in such a way that it could also be used to post process triage collections to allow a consistent analysis experience.  Allowing analysts to spend more time analyzing and less time messing with various forensic tools and options.
It has been, from the very begining that,
<a href=https://github.com/OMENScan/AChoir> AChoir </a> and 
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a>
could be used for live response, 
<a href=https://github.com/OMENScan/AChoirX/tree/master/ToolsBuiltWithAChoirX/AChDBox> dead-box</a>) 
collection, and artifact post processing.  And with 
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a>
that capabilty extends to Windows, OSX, and Linux.

After creating 
<a href=https://github.com/OMENScan/AChoirX> AChoir(X) </a>
My next step was to create an automated forensic reporting tool.  A tool that could read a triage collection and organise the most common artifacts into a single HTML report file for simple navigation and analysis.  That was realized with
<a href=https://github.com/OMENScan/AChReport> AChReport</a>.

But
<a href=https://github.com/OMENScan/AChReport> AChReport</a>
was written to report on 
<a href=https://github.com/OMENScan/AChoirX> AChoir(X) </a>
collections.  As I ran into triage collection from other tools, I decided to change 
<a href=https://github.com/OMENScan/AChReport> AChReport</a> to
<a href=https://github.com/OMENScan/TriageReport> TriageReport</a> 
and allow it to report on nearly any type of triage collection.

As I began to use 
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a> to create
<a href=https://github.com/OMENScan/AChoirX/tree/master/ToolsBuiltWithAChoirX> additional forensic tools</a> such as 
<a href=https://github.com/OMENScan/AChoirX/tree/master/ToolsBuiltWithAChoirX/Win-VoLoki>an automated Memory analysis tool</a> tying 
<a href=https://www.volatilityfoundation.org/3> volatility</a> to 
<a href=https://github.com/Neo23x0/Loki>LOKI</a>, or an 
<a href=https://github.com/OMENScan/AChoirX/blob/master/Scripts/PlasoX.ACQ>automated Timeliner tool that runs 
<a href=https://github.com/log2timeline/plaso> Plaso</a> against a triage collection, I began to see that a completely automated and flexible forensic pipeline was possible.

This has brought me to this project: Auto4n6.

Auto4n6 uses
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a> 
and several other FOSS forensic tools (Including 
<a href=https://github.com/OMENScan/TriageReport> TriageReport</a>)
to create an automated pipeline that processes both memory images and triage collections.  A memory dump or triage collection is simply copied into a directory and Auto4n6 takes over, parsing and analyzing the data to create a comprehsive analysis and reporting pipeline.

# How does it work?
Auto4n6 is currently in an Alpha (v0.01) state so it takes quite a bit of configuration to make it work.  That will change as I improve the software.  Essentially AChoirX runs several FOSS Forensic utilities and organizes them into a consistent set of outputs for the forensic analyst.  Below I will outline the tools it uses and how to configure them so that an anlyst can customize it to their own needs and preferences.

# Step 1: The AChoirX Scripts
Auto4n6 currently consists of four (4) 
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a> scripts
<ul>
 <li><a href=https://github.com/OMENScan/Auto4n6/blob/main/AChoir.ACQ> The main driver script</a></li>
 <li><a href=https://github.com/OMENScan/Auto4n6/blob/main/MemProcess.ACQ> The memory dump processing script</a></li>
 <li><a href=https://github.com/OMENScan/Auto4n6/blob/main/ColProcess.ACQ> The triage collection processing script</a></li>
 <li><a href=https://github.com/OMENScan/Auto4n6/blob/main/PlasoX.ACQ> The <a href=https://github.com/log2timeline/plaso> Plaso</a> timelining script</a></li>
</ul>

# Step 2: The Auto4n6 Main Driver Script
First it is important to note that 
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a> 
can function in "Blocked" or "UnBlocked" mode.  In Blocked mode a program waits until it's previous sub-processes wait until they complete to run the next process.  In UnBlocked mode a program can run multiple sub-process simultaneously. Auto4n6 works in UnBlocked mode, meaning that multiple triage and memory parsing process can run at the same time.  This makes processing MUCH faster but imtroduces some complication.  All you really need to know is that Auto4n6 can run parse multiple memory dumps and triage collections at the same time.  That means that monitoring the console can be confusing as you see multiple processes executing at the same time.  Auto4n6 does not have any issues with this, but it can be confusing to watch the console as it displays messages across multiple parsing routines.

## Syslog
By default Auto4n6 logs to the console, to a unique individual log file (per processing routine) and to a local Syslog (<b>127.0.0.1</b>).  If you have an external Syslog, you can change the syslog parameters to point to your centralized syslog. If you prefer not to syslog the console message, this can be commented out.

## The Memory Dump Processing Queue
By default, Auto4n6 waits for Memory Dumps to appear in <b>C:\Auto-Mem</b>.  This can be changed in the script to point to a different directory of your choosing.

## The Triage Collection Processing Queue
By default, Auto4n6 waits for Triage collections to appear in <b>C:\Auto-Col</b>.  This can be changed in the script to point to a different directory of your choosing.

## What is Where?
Auto4n6 separates each processing run in a unique directory to ensure that one processing run doesn't step on another.  Since Auto4n6 is designed to be able to process at scale, multiple processing runs can be running simultaneously.  The need to understand which processing run is associated with which memory/triage collection becomes an important requirement.

To address this Auto4n6 keeps two(2) running files:
<ul>
 <li><b>Auto4n6.csv</b> - Shows which processing run is associated with which memory/triage collection input in CSV format</li>
 <li><b>Auto4n6.HTML</b> - Shows which processing run is associated with which memory/triage collection input in an HTML file</li>
</ul>

Using these files, an analyst can determine which input file is associate with which output directory.  To make this clearer, I recommend that memory dumps and Triage Collections be named uniquely to help in quicker matching of where the output is located.

# Step 3: The Memory Dump Processing Script
Once Auto4n6 detects a file in the Memory Dump directory (queue), it will create a new Auto4n6 directory and move the memory dump to the new directory.  This directory can be seen in the Main Driver script, and the default is <b>C:\Auto-Mem</b>.

The memory dump processing script will then run several 
<a href=https://www.volatilityfoundation.org/3> volatility</a>
commands against the memory dump to extract things like network connections and processes. Once the extraction is complete, Auto4n6 will run 
<a href=https://github.com/Neo23x0/Loki>LOKI</a> against all of the extracted data.

For 
<a href=https://www.volatilityfoundation.org/3> volatility</a> to work properly 
<a href=https://www.python.org/downloads/>Python 3</a> must be installed on the system.  Auto4n6 expects
<a href=https://www.volatilityfoundation.org/3> volatility</a> to be installed in 
<b>C:\Auto4n6\Volatility3</b> and for
<a href=https://github.com/Neo23x0/Loki>LOKI</a> to be installed in
<b>C:\Auto4n6\Loki</b> - These locations can be changed in the <b>MemProcess.ACQ</b> Script, but I recommend keeping the default locations.

Please note that both 
<a href=https://www.volatilityfoundation.org/3> volatility</a> and 
<a href=https://github.com/Neo23x0/Loki>LOKI</a>
are highly configurable.  You can add, change or delete their parameters in the <b>MemProcess.ACQ</b> script as well as configure their own unique settings (i.e. add additional YARA rules to LOKI) to fully customize your Auto4n6 parsing and analysis environment.


# Step 4: The Triage Collection Processing Script
The Triage Collection Processing script does several things:
<ul>
 <li> Move the Triage Collection from the queue (the default is <b>C:\Auto-Col</b>) to a uniquely named acquisition sub-directory</li>
 <li> Unzip the Triage Collection into a sub-directory called <b>Triage</b></li>
 <li> Run <a href=https://github.com/OMENScan/triagereport>TriageReport</a> against the Triage Collection</li>
 <li> The Triage Report will be written to a sub-directory called <b>TriageReport</b></li>
 <li> Run <a href=https://github.com/log2timeline/plaso> Plaso</a> (Log2Timeline) against the Triage Collection to create a Super Timeline</li>
</ul>

For this to work properly, you will need to edit the 
<a href=https://github.com/OMENScan/TriageReport> TriageReport</a> 
Confiquration file to point to all the artifacts in the collection. 

The Default Configuration File will be in <b>&Dir\TriageReport\AChReport.cfg</b> but that can be changed in the <b>ColProcess.ACQ</b> Script. 

For <a href=https://github.com/OMENScan/TriageReport> TriageReport</a> to work properly the following setup is necessary:
<ul>
 <li>Python 3 must be installed on the system.</li>
 <li><a href=https://github.com/OMENScan/triagereport>TriageReport</a> must be installed in the <b>\TriageReport<b> sub-directory under the Auto4n6 Root Directory.
 <li><a href=https://www.microsoft.com/en-us/download/details.aspx?id=24659>Microsoft Log Parser</a> must be installed in the Auto4n6 Root Directory.
 <li><a href=https://github.com/WithSecureLabs/chainsaw>Chainsaw</a> must be installed in the <b>\Chainsaw<b> sub-directory under the Auto4n6 Root Directory.
 <li><a href=https://github.com/WithSecureLabs/chainsaw>Chainsaw</a> must be installed in the <b>\Chainsaw<b> sub-directory under the Auto4n6 Root Directory.
 <li><a href=https://github.com/keydet89/RegRipper3.0>RegRipper 3</a> must be installed in the <b>\RRV\RegRipper3.0-master<b> sub-directory under the Auto4n6 Root Directory.
 <li><a href=https://ericzimmerman.github.io/#!index.md>LECmd and SBECmd</a> must be installed in the <b>\Sys<b> sub-directory under the Auto4n6 Root Directory.
 <li><a href=https://www.nirsoft.net/utils/win_prefetch_view.html>WinPrefetchView</a> must be installed in the <b>\Sys<b> sub-directory under the Auto4n6 Root Directory.
 <li><a href=https://www.7-zip.org/download.html>Standalone 7-Zip</a> must be installed in the <b>\Utils\7z<b> sub-directory under the Auto4n6 Root Directory.
 <li><a href=http://malware-hunters.net/wp-content/downloads/MFTDump_V.1.3.0.zip>MFTDump</a> must be installed in the <b>\DSK<b> sub-directory under the Auto4n6 Root Directory.
</ul>


# Step 5: The <a href=https://github.com/log2timeline/plaso> Plaso</a> Timeliner Processing Script
After running <a href=https://github.com/OMENScan/TriageReport> TriageReport</a> 
Auto4n6 will call the <b>PlasoX.ACQ</b> script, this script runs 
<a href=https://github.com/log2timeline/plaso> Plaso</a> <b>Log2Timeline.exe</b> against the Triage Collection.

When <b>Log2Timeline</b> is complete, Auto4n6 will then run <b>psort.exe</b> to convert the timeline to CSV format.

Auto4n6 expects <a href=https://github.com/log2timeline/plaso> Plaso</a> to be installed in the <b>\Plaso<b> sub-directory under the Auto4n6 Root Directory. 

At this time, Auto4n6 will not do any additional processing of the timeline.  It is up to the analyst to decide how to use the timeline for their analysis.

# Step 6: ?
This is Auto4n6 Version 0.01 - Additional functionality will added as I improve the system.

