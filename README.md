space oddity
------------

A log parser for a fictional NASA website, for Insight Data Engineering.

This code runs using the standard Python library (2.7).

See `src/process_log.py --help` for usage.


features
--------

1. List the top 10 most active host/IP addresses that have accessed the site. Writes to `hosts.txt`.
2. Identify the 10 resources that consume the most bandwidth on the site. Writes to `resources.txt`.
3. List the top 10 busiest (or most frequently visited) 60-minute periods. Writes to `hours.txt`.
4. Detect patterns of three failed login attempts from the same IP address over 20 seconds so that all further attempts to the site can be blocked for 5 minutes. Log those possible security breaches. Writes to `blocked.txt`.

The following illustration details feature 4:

![Feature 4 illustration](images/feature4.png)

data
----

The full dataset this runs on is here: https://drive.google.com/file/d/0B7-XWjN4ezogbUh6bUl1cV82Tnc/view

## Description of Data

The log looks like this

    in24.inetnebr.com - - [01/Aug/1995:00:00:01 -0400] "GET /shuttle/missions/sts-68/news/sts-68-mcc-05.txt HTTP/1.0" 200 1839
    208.271.69.50 - - [01/Aug/1995:00:00:02 -400] “POST /login HTTP/1.0” 401 1420
    208.271.69.50 - - [01/Aug/1995:00:00:04 -400] “POST /login HTTP/1.0” 200 1420
    uplherc.upl.com - - [01/Aug/1995:00:00:07 -0400] "GET / HTTP/1.0" 304 0
    uplherc.upl.com - - [01/Aug/1995:00:00:08 -0400] "GET /images/ksclogo-medium.gif HTTP/1.0" 304 0

and is parsed using the Request class into an object containing:

+ host making request
+ timestamp
+ python datetime object
+ HTTP request method
+ resource requested
+ HTTP protocol
+ reply code
+ reply size in bytes


The input is assumed to be utf-8, and non-conformant characters are dropped. In the rare case that this renders the line of a log unparsable, the effected fields will be returned as `None`. This allows the parser to salvage parsable sections of the malformed line.

directory structure
-------------------

the directory structure of the repo is as follows:

    ├── README.md
    ├── run.sh
    ├── src
    │   └── process_log.py
    ├── log_input
    │   └── log.txt
    ├── log_output
    |   └── hosts.txt
    |   └── hours.txt
    |   └── resources.txt
    |   └── blocked.txt
    ├── insight_testsuite
        └── run_tests.sh
        └── tests
            └── test_features
            |   ├── log_input
            |   │   └── log.txt
            |   |__ log_output
            |   │   └── hosts.txt
            |   │   └── hours.txt
            |   │   └── resources.txt
            |   │   └── blocked.txt
            ├── your-own-test
                ├── log_input
                │   └── your-own-log.txt
                |__ log_output
                    └── hosts.txt
                    └── hours.txt
                    └── resources.txt
                    └── blocked.txt

tests
-----

The tests are called from `run_tests.sh` in the `insight_testsuite/run_tests.sh` and the tests exist in the `insight_testsuite/tests` folder.

No extra tests were written due to time constraints.

