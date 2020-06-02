#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static const uint64_t BREAKPOINTS[] = {
    0x4bb5a3,  0x4c05c3,  0x4c56c3,  0x4ca603,
    0x4cfb63,  0x4d4f03,  0x4da2a3,  0x4df803,
    0x4e4ac3,  0x4ea023,  0x4eef63,  0x4f4303,
    0x4f95c3,  0x4feb23,  0x503ec3,  0x509503,
    0x50ea63,  0x513e03,  0x519363,  0x51e8c3,
    0x523e23,  0x5290e3,  0x52e2c3,  0x5339e3,
};

int main()
{
    pid_t pid;
    struct user_regs_struct regs;
    uint64_t code, input_addr, input_data;
    int pipefd[2];
    int status, i;
    char flag;

    // Bind CPU 0.
    // It seems ptrace don't work well with goroutes if running on a multi-core CPU.
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
    {
        perror("sched_setaffinity");
        exit(1);
    }

    pipe(pipefd);

    pid = fork();
    if (pid == 0)
    {
        /* Child side */

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        {
            perror("PTRACE_TRACEME");
            exit(1);
        }

        dup2(pipefd[0], STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        close(pipefd[1]);

        if (execl("./go-flag", "go-flag", NULL) == -1)
        {
            perror("execl");
            exit(1);
        }
    }
    else if (pid == -1)
    {
        perror("fork");
        exit(1);
    }
    else
    {
        /* Parent side */

        waitpid(pid, &status, 0);
        if (!WIFSTOPPED(status))
        {
            fputs("Failed to execute go-flag\n", stderr);
            exit(1);
        }

        // Send a fake flag to go-flag
        for (i = 0; i < 0x20; ++i)
            write(pipefd[1], "A", 1);
        close(pipefd[0]);
        close(pipefd[1]);

        // Enable breakpoints
        for (i = 0; i < sizeof(BREAKPOINTS) / sizeof(uint64_t); ++i)
        {
            code = ptrace(PTRACE_PEEKTEXT, pid, BREAKPOINTS[i], NULL);
            if ((code & 0xFFFFFF) == 0xf68440) /* test sil, sil */
            {
                code = (code &(~0xFF)) | 0xcc;
                ptrace(PTRACE_POKETEXT, pid, BREAKPOINTS[i], code);
            }
        }

        // Resume
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        i = 0;
        while (i < sizeof(BREAKPOINTS) / sizeof(uint64_t))
        {
            waitpid(pid, &status, 0);
            if (!WIFSTOPPED(status))
            {
                fputs("Child exited unexpectedly\n", stderr);
                exit(1);
            }

            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            code = ptrace(PTRACE_PEEKTEXT, pid, regs.rip - 1, NULL);
            if ((code & 0xFFFFFF) == 0xf684cc)
            {
                // Read flag
                flag = regs.rsi & 0xFF;

                // Replace the fake flag so go-flag won't fail by the incorrect flag
                input_addr = regs.rbx + 4;
                input_data = (ptrace(PTRACE_PEEKDATA, pid, input_addr, NULL)) &(~0xFF) | flag;
                ptrace(PTRACE_POKEDATA, pid, input_addr, input_data);

                // Disable the breakpoint
                code = (code &(~0xFF)) | 0x40;
                ptrace(PTRACE_POKETEXT, pid, regs.rip - 1, code);

                putchar(flag);
                ++i;
            }
            ptrace(PTRACE_CONT, pid, NULL, NULL);
        }
        putchar(0xa);

        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
    }

    return 0;
}
