## Code in C programming language that utilizes an access control logging system tool in C, and a simple ransomware to test the tool in practice.

### The access control logging system monitors and keeps track of every file access and modification that occurs in the system.

Folder contains:
* ransomware.sh [directory name] [X]
"Contains the bash script that uses the c code in test_aclog.c in order to create X files in the directory given.
Then encrypt those files in the same folder and delete the original ones."
*This implementation was used in order to achieve calling the fopen()
function and thus create log file entries for each file access.

* logger.c
"Contains the C code used for utilizing the fopen() and fwrite() functions to be preloaded,
 which in turn call the original fopen() and fwrite() respectivelly.
 The new functions log the file accesses in a file_loffing.log file."

* acmonitor.c
"Contains the C code used for monitoring the users file accesses and classifiying the results acording to the operation requested
(Use comand ./acmonitor -h for tool usage)."

* test_aclog.c
"Contains the C code used by the ransomware.
 More specifically
 -c: generates X files where X is given as an argument containing their filename.
 -e: Creates filename.encrypt file where filename is given as an argument."

* Makefile
"make all <--Compile c files."

* test_dir
"passed as argument when calling the ransomware initially no contents."
 Example: $ sh ransomware.sh test_dir 20


	<thodorischa@gmail.com>
