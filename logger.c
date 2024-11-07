#define _GNU_SOURCE
#include <libgen.h>
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

typedef struct entry {
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */
	char *date; /* file access date */
	char *time; /* file access time */
	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */
} entry;

const char* ENTRY_FORMAT_OUT =	"%d, %d, %d, %s, %s, %s, %s\n";

FILE *
fopen(const char *path, const char *mode){

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
	int accTy = 1;
	if( access( path, F_OK ) == -1 ) {
			accTy = 0;
	}
	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	time_t now;
	time(&now);
	struct tm *local = localtime(&now);
	char str_date[9];
	char str_time[9];
	strftime(str_date, sizeof(str_date), "%x", local);
	strftime(str_time, sizeof(str_time), "%X", local);

	int actDen = 0;
	if( access( path, R_OK ) == -1 ) {
			actDen = 1;
	}
	unsigned char *md5_result = NULL;
	unsigned char *buf;
	long filesize;

	fseek(original_fopen_ret, 0, SEEK_END);
  filesize = ftell(original_fopen_ret);
  fseek(original_fopen_ret, 0, SEEK_SET);

	buf = malloc(filesize);
  fread(buf, filesize, 1, original_fopen_ret);

	md5_result = malloc(16);
	MD5(buf, sizeof(buf), md5_result);
	if (filesize==0) {
		for (size_t i = 0; i < 16; i++) {
			md5_result[i]='0';
		}
	}
	entry newEntry = {
		.uid = getuid(),
		.access_type = accTy,
		.action_denied = actDen,
		.date = str_date,
		.time = str_time,
		.file = basename((char*)path),
		.fingerprint = (char*)md5_result
	};

	char *logpath = "./file_logging.log";
	FILE *log_ret;
	if( access( logpath, F_OK ) == -1 ) {
			log_ret = (*original_fopen)(logpath,"w");
			fclose(log_ret);
	}
	log_ret = (*original_fopen)(logpath,"r+");
	if (log_ret==NULL) {
		printf("Error opening log file\n");
		exit(1);
	}
	fseek(log_ret, 0L, SEEK_END);
	fprintf(log_ret, ENTRY_FORMAT_OUT, newEntry.uid, newEntry.access_type,
		 newEntry.action_denied, newEntry.date, newEntry.time , newEntry.file,
		 newEntry.fingerprint);

	fclose(log_ret);
 	free(md5_result);
  free(buf);
	return original_fopen_ret;
}


size_t
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	/* call the original fopen function */
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	//Find out name of file
	char path[128];
	char result[128];
	int fd = fileno(stream);
	sprintf(path, "/proc/self/fd/%d", fd);
	int test = readlink(path, result, sizeof(result)-1);
	result[test] = '\0';

	time_t now;
	time(&now);
	struct tm *local = localtime(&now);
	char str_date[9];
	char str_time[9];
	strftime(str_date, sizeof(str_date), "%x", local);
	strftime(str_time, sizeof(str_time), "%X", local);

	int actDen = 0;
	if( access( result, W_OK ) == -1 ) {
			actDen = 1;
	}
	unsigned char *md5_result;
	unsigned char *buf;
	long filesize;
	fseek(stream, 0L, SEEK_END);
  filesize = ftell(stream);
  fseek(stream, 0L, SEEK_SET);

	buf = malloc(filesize);
  fread(buf, filesize, 1, stream);

	md5_result = malloc(16);
	MD5(buf, sizeof(buf), md5_result);

	entry newEntry = {
		.uid = getuid(),
		.access_type = 2,
		.action_denied = actDen,
		.date = str_date,
		.time = str_time,
		.file = basename(result),
		.fingerprint = (char*)md5_result
	};
	char *logpath = "./file_logging.log";
	FILE *log_ret;
	if( access( logpath, F_OK ) == -1 ) {
			log_ret = (*original_fopen)(logpath,"w");
			fclose(log_ret);
	}
	log_ret = (*original_fopen)(logpath,"r+");
	if (log_ret==NULL) {
		printf("Error opening log file\n");
		exit(1);
	}
	fseek(log_ret, 0L, SEEK_END);
	fprintf(log_ret, ENTRY_FORMAT_OUT, newEntry.uid, newEntry.access_type,
		 newEntry.action_denied, newEntry.date, newEntry.time , newEntry.file,
		 newEntry.fingerprint);
	fclose(log_ret);
 	free(md5_result);
  free(buf);

	return original_fwrite_ret;
}
