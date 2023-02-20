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
<a href=https://github.com/OMENScan/AChoirX/blob/master/Scripts/PlasoX.ACQ>automated Timeliner tool that runs Plaso</a>
against a triage collection, I began to see that a completely automated and flexible forensic pipeline was possible.

This has brought me to this project: Auto4n6.

Auto4n6 uses
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a> 
and several other FOSS forensic tools (Including 
<a href=https://github.com/OMENScan/TriageReport> TriageReport</a>)
to create an automated pipeline that processes both memory images and triage collections.  A memory dump or triage collection is simply copied into a directory and Auto4n6 takes over, parsing and analyzing the data to create a comprehsive analysis and reporting pipeline.

# How does it work?
Auto4n6 is currently in an Alpha (v0.01) state so it takes quite a bit of configuration to make it work.  That will change as I improve the software.  Essentially AChoirX runs several FOSS Forensic utilities and organizes them into a consistent set of outputs for the forensic analyst.  Below I will outline the tools it uses and how to configure them so that an anlyst can customize it to their own needs and preferences.

# Step1: The AChoirX Scripts
Auto4n6 currenlty consists of four (4) 
<a href=https://github.com/OMENScan/AChoirX> AChoirX </a> scripts
<ul>
 <li><a href=https://github.com/OMENScan/Auto4n6/blob/main/AChoir.ACQ> The main driver script</a></li>
 <li><a href=https://github.com/OMENScan/Auto4n6/blob/main/MemProcess.ACQ> The memory dump processing script</a></li>
 <li><a href=https://github.com/OMENScan/Auto4n6/blob/main/ColProcess.ACQ> The triage collection processing script</a></li>
 <li><a href=https://github.com/OMENScan/Auto4n6/blob/main/PlasoX.ACQ> The Plaso timelining script</a></li>
</ul>



