/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 *
 * @author Junshang Jia <junshanj@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);
bool builtin_command(struct cmdline_tokens *tokens);
void wait_fg_job(pid_t pid);
void process_bg_fg_command(struct cmdline_tokens *tokens);

/**
 * @brief <Write main's function header documentation. What does main do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

void process_bg_fg_command(struct cmdline_tokens *tokens) {

    pid_t pid;
    jid_t jid;
    if (tokens->argv[1] == NULL) {
        sio_printf("%s command requires PID or %%jobid argument\n",
                   tokens->argv[0]);
        return;
    }
    if (tokens->argv[1][0] == '%') {
        jid = atoi(&tokens->argv[1][1]);
        if (jid > 0 && job_exists(jid)) {
            pid = job_get_pid(jid);

        } else {
            if (jid <= 0) {
                sio_printf("%s: argument must be a PID or %%jobid\n",
                           tokens->argv[0]);

            } else {
                sio_printf("%%%d: No such job\n", jid);
            }

            return;
        }
    } else if ((pid = atoi(&tokens->argv[1][0])) > 0 && job_from_pid(pid)) {
        jid = job_from_pid(pid);

    } else {
        if (pid <= 0) {
            sio_printf("%s: argument must be a PID or %%jobid\n",
                       tokens->argv[0]);

        } else {
            sio_printf("%d:No such job\n", pid);
        }

        return;
    }
    job_state state = tokens->builtin == BUILTIN_BG ? BG : FG;
    kill(-pid, SIGCONT);
    job_set_state(jid, state);
    if (state == BG) {
        sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
    } else {
        sigset_t mask;
        sigemptyset(&mask);
        while (fg_job() > 0) {
            sigsuspend(&mask);
        }
    }
}

bool builtin_command(struct cmdline_tokens *tokens) {
    sigset_t mask, prev_mask;
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    if (tokens->builtin == BUILTIN_QUIT) {

        exit(0);
    }

    if (tokens->builtin == BUILTIN_JOBS) {
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        list_jobs(STDOUT_FILENO);
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);

        return true;
    }

    if (tokens->builtin == BUILTIN_BG || tokens->builtin == BUILTIN_FG) {
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        process_bg_fg_command(tokens);
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return true;
    }

    return false;
}
/**
 * @brief <What does eval do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {

    parseline_return parse_result;
    struct cmdline_tokens token;
    pid_t pid;
    sigset_t mask, prev_mask;
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    job_state state = parse_result == PARSELINE_BG ? BG : FG;

    if (!builtin_command(&token)) {

        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        if ((pid = fork()) == 0) {
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);

            setpgid(pid, pid);

            // sigprocmask(SIG_SETMASK, &free_all, NULL);
            if (execve(token.argv[0], token.argv, environ) < 0) {
                sio_printf("%s: Command not found.\n", token.argv[0]);
                exit(0);
            }
        } else {

            if (parse_result == PARSELINE_FG) {
                add_job(pid, state, cmdline);

                while (fg_job() > 0) {

                    sigsuspend(&prev_mask);
                }

                sigprocmask(SIG_SETMASK, &prev_mask, NULL);

            } else {
                jid_t jid = add_job(pid, state, cmdline);

                sio_printf("[%d] (%d) %s\n", jid, pid, cmdline);
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            }
        }
    }

    // TODO: Implement commands here.
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief <What does sigchld_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    int status;
    pid_t pid;
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {

        jid_t jid = job_from_pid(pid);

        if (WIFSIGNALED(status)) {

            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                       WTERMSIG(status));
        }
        if (WIFSTOPPED(status)) {

            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                       WSTOPSIG(status));

            job_set_state(jid, ST);
        }
        if (job_get_state(jid) == BG || job_get_state(jid) == FG) {
            delete_job(jid);
        }
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief <What does sigint_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    jid_t jid;
    pid_t pid;

    sigset_t mask_all, prev;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev);
    if ((jid = fg_job()) > 0) {
        // sio_printf("the jid is %d\n",jid);
        pid = job_get_pid(jid);

        kill(-pid, SIGINT);
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief <What does sigtstp_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    jid_t jid;
    pid_t pid;
    sigset_t mask_all, prev;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev);
    if ((jid = fg_job()) > 0) {
        pid = job_get_pid(jid);

        kill(-pid, SIGTSTP);
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
