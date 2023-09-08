#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>

char			*nop_finder(const void *ptr, size_t n, char *s)
{
	char	*s2;
	int		i;
	int		j;

	i = 0;
	j = 0;
	s2 = (char*)ptr;
	if (s[i] == '\0')
		return ((char*)s2);
	while (i < n)
	{
		if (s[j] == '\0' && s2[j] != '\x90')
			return ((char*)&s2[i]);
		if (s2[i + j] == s[j] && i + j < n)
			j++;
		else
		{
			j = 0;
			i++;
		}
	}
	return (0);
}

int				main(int ac, char **av)
{
	int		fd;
	size_t	size;
	char	*ptr;
	char	*nop;

	if ((fd = open("./Death", O_RDWR)) < 0)
		return (-1);
	if ((size = lseek(fd, 0, SEEK_END)) < 0)
		return (-1);
	if ((ptr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		return (-1);
	while ((nop = nop_finder(ptr, size, "\x90\x90\x90\x90\x90\x90\x90\x90")) > 0)
	{
		*(nop) = '\x50';
		*(nop + 1) = '\x03';
		*(nop + 2) = '\xc0';
		*(nop + 3) = '\x03';
		*(nop + 4) = '\xc0';
		*(nop + 5) = '\x03';
		*(nop + 6) = '\xc0';
		*(nop + 7) = '\x58';
		printf("%p >%lx<\n", nop, *(long int*)nop);
	}
	while ((nop = nop_finder(ptr, size, "\x90\x90\x90\x90\x90")) > 0)
	{
		*(nop) = '\x74';
		*(nop + 1) = '\x03';
		*(nop + 2) = '\x75';
		*(nop + 3) = '\x01';
		*(nop + 4) = '\xe8';
		printf("%p >%lx<\n", nop, *(long int*)nop);
	}
	lseek(fd, 0, SEEK_SET);
	write(fd, ptr, size);
	return (0);
}