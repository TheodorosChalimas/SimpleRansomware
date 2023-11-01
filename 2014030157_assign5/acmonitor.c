#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

typedef struct entry {
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */
	char date[9]; /* file access date */
	char time[9]; /* file access time */
	char file[128]; /* filename (string) */
	char fingerprint[16]; /* file fingerprint */
} entry;

const char* ENTRY_FORMAT_IN =	"%d, %d, %d, %[^,], %[^,], %[^,], %s";
const char* ENTRY_FORMAT_OUT =	"%d, %d, %d, %s, %s, %s, %s\n";

entry* lineToEntry(char *line)
{
  entry *newEntry = malloc(sizeof(entry));

  sscanf(line, ENTRY_FORMAT_IN, &newEntry->uid, &newEntry->access_type,
			&newEntry->action_denied, newEntry->date, newEntry->time ,
      newEntry->file, newEntry->fingerprint);

  return newEntry;
}

void
usage(void)
{
	printf(
       "\n"
       "usage:\n"
       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
			 "-v <number of files>, Prints the total number of files created"
			 "in the last 20 minutes and repports suspicious behaviour if its bigger than the input\n"
			 "-e, Prints all files that were encrypted by the ransomware\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void
list_unauthorized_accesses(FILE *log)
{
	char line[200];
	entry* newEntry;
	char buffer[140];
	int numOFActs = 0;
	char **malAct = (char**)calloc(numOFActs, sizeof(128));
	int exist = 0;

	while(!feof(log)){
		fgets(line,sizeof(line),log);
	  newEntry = lineToEntry(line);
	//Check if action was denied
		if (newEntry->action_denied == 1) {
	/*Logged potential malitious action(we dont care if its repetitive)
		P.S. If we did we would count the repetitions inside the loop below in an int Count[numOFActs]*/
			sprintf(buffer, "%d %s", newEntry->uid, newEntry->file);
			for (size_t i=0; i<numOFActs; i++) {
				if(strcmp(malAct[i], buffer)==0){
					exist = 1;
				}
			}
	//Unlogged potential malitious action from one user to specific file without permission
			if (exist==0) {
				numOFActs++;
				malAct = (char**)realloc(malAct, numOFActs*sizeof(*malAct));
				malAct[numOFActs-1] = (char*)malloc(sizeof(128));
				strcpy(malAct[numOFActs-1], buffer);
			}
			exist = 0;
		}
	}
	int tempid[numOFActs];
	int numOfIds = 1;
	int *ids = (int*)calloc(numOfIds,sizeof(int));

	char tempfilename[128];
	int times = 0;
	//Keep track of id's of potential malitous actions
	for (size_t i=0; i<numOFActs; i++) {
		sscanf(malAct[i], "%d %s", &tempid[i], tempfilename);
	}
	ids[0] = tempid[0];
	int flag = 0;
	//Check how many times each id came up in potential malitious actions
	for (size_t j=0; j<numOfIds; j++) {
		for (size_t i=1; i<numOFActs; i++) {
			if(tempid[i]==ids[j]){
					times++;
			}else if(flag == 0){
				numOfIds++;
				ids = (int*)realloc(ids, numOfIds*sizeof(int));
				ids[numOfIds-1] = tempid[i];
				flag =1;
			}
		}
		if(times>7){
			printf("MALICIOUS USERS:\n" );
			printf("User with id: %d , tried to access %d different files with no permission\n", ids[j],times);
		}
		times = 0;
	}


	free(newEntry);
	free(malAct);
	return;
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	char line[200];
	entry* newEntry;
	char temp[16];
	int capacity = 0;
	int *users = (int*)calloc(capacity, sizeof(int));
	int *mod = (int*)calloc(capacity, sizeof(int));
	int exist = 0;

	while(!feof(log)){
		fgets(line,sizeof(line),log);
	  newEntry = lineToEntry(line);
		//check for file
		if (strcmp(file_to_scan, newEntry->file) == 0) {
		//Check if if file has been modified in this log entry
			if(strcmp(temp, newEntry->fingerprint) != 0 && newEntry->access_type==2 && newEntry->action_denied != 1){
				strcpy(temp, newEntry->fingerprint);
		//Check if user who made the change has already been logged
				for (size_t i=0; i<capacity; i++) {
					if(users[i] == newEntry->uid){
						exist = 1;
						mod[i]++;
					}
				}
		//Log new user who modified the file
				if (exist==0) {
					capacity++;
					users = (void*)realloc(users, capacity*sizeof(int));
					mod = (void*)realloc(mod, capacity*sizeof(int));
					users[capacity-1] = newEntry->uid;
					mod[capacity-1] = 1;
				}
				exist = 0;
			}
		}
	}
	//print results
	for (size_t i=0; i<capacity; i++) {
		printf("The user with id: %d,\t modified the file: %s, %d times\n", users[i], file_to_scan, mod[i]);
	}
		free(newEntry);
	return;
}



void list_last_20_mins(FILE *log, int min){
	entry* newEntry;
	char line[200];
	int created;
	char temp[9];
	int numOfFiles = 0;
	int H,M,S;
	int LH,LM,LS;

	time_t now;
	time(&now);
	struct tm *local = localtime(&now);
	char str_date[9];
	char str_time[9];
	strftime(str_date, sizeof(str_date), "%x", local);
	strftime(str_time, sizeof(str_time), "%X", local);
	sscanf( str_time, "%d:%d:%d", &LH, &LM, &LS );

	while(!feof(log)){
		fgets(line,sizeof(line),log);
		newEntry = lineToEntry(line);
		created = newEntry->access_type;
		strcpy(temp, newEntry->date);
		//check if file was created today
		if (strcmp(str_date,temp) == 0 && created == 0) {
				strcpy(temp, newEntry->time);
				sscanf( temp, "%d:%d:%d", &H, &M, &S );
				//check if file was created in last 20 mins
				if (H == LH && M+20 >= LM) {
					numOfFiles++;
				}else if (H == LH-1 && M >= LM+40) {
					numOfFiles++;
				}
		}
	}
	printf("Local date and time is %s", asctime(local));
	if (numOfFiles >= min) {
	printf("In the past 20 minutes more than %d files were created: %d (Suspicious)\n", min,numOfFiles);
	} else {
	printf("In the past 20 minutes less than %d files were created: %d (Not suspicious)\n", min,numOfFiles);
	}
	free(newEntry);
	return;
}


void list_encrypted(FILE *log){
	entry* newEntry;
	char line[200];
	char temp[128];
	char *ext;
	char *enc = ".encrypt";
	int created;
	while(!feof(log)){
		fgets(line,sizeof(line),log);
		newEntry = lineToEntry(line);
		strcpy(temp, newEntry->file);
		created = newEntry->access_type;
		ext = strrchr(temp, '.');
		if (ext){
			//check if extention of file = .encrypt
			if (strcmp(ext,enc)==0 && created != 2) {
				printf("%s\n", temp);
			}
		}
	}
	free(newEntry);
	return;
}



int
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:mv:e")) != -1) {
		switch (ch) {
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'v':
			list_last_20_mins(log, atoi(optarg));
			break;
		case 'e':
			list_encrypted(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;

	return 0;
}
