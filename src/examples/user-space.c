#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#define DEVICE		"/dev/mydmx0"

void send(int fd, unsigned char *buf, int count)
{
	int retval = 0;

	retval = write(fd, buf, count);
	if (retval < 0)
		fprintf(stderr, "could not send buffer to %d\n", retval);
}

int main(int argc, char *argv[])
{
	int fd;
	char *dev = DEVICE;

	fd = open(dev, O_WRONLY);
	if (fd == -1) {
		perror("open");
		exit(1);
	}

   unsigned char buffer[512];
   int j;
	int k;

   for(j=0;j<512;j++) { buffer[j] = 0; }

	send(fd, buffer, sizeof(buffer));

	buffer[3] = 0xff;

	for(j=0;j<3;j++)
   {
      for(k=255;k>=0;k=k-2)
      {
         buffer[j] = k;

			send(fd, buffer, sizeof(buffer));
		}
	}

	buffer[3] = 0;

	send(fd, buffer, sizeof(buffer));

	close(fd);

	return EXIT_SUCCESS;
}

