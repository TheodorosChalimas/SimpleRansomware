#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/fsuid.h>
#include <unistd.h>
#include <getopt.h>

int main(int argc, char **argv)
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[30];
	int opt = 0;
	int times;

	while ((opt = getopt(argc,argv,"c:e:"))) {

		switch (opt) {
			case 'c':
				times = atoi(optarg);

				for (i = 0; i < times; i++) {
					sprintf(filenames, "test_dir/file_%d.txt", i);
					file = fopen(filenames, "w+");
					if (file == NULL)
						printf("fopen error\n");
					else {
						bytes = fwrite(filenames, strlen(filenames), 1, file);
						fclose(file);
					}
				}

				printf("%d files created\n", times);
				break;
			case 'e':
				file = fopen(optarg, "w+");
				fclose(file);
				break;
			default:
				return 0;
		}
	}
return 0;

}
