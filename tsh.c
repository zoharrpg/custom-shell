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
#include <sys/stat.h>
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

/**
 * @brief The function `process_bg_fg_command` processes a background or
 * foreground command by obtaining the process ID or job ID, setting the job
 * state, and  send SIGCONT to make the process to run background and foreground
 * The bg job command resumes job by sending it a SIGCONT signal, and then runs
 * it in the background. The job argument can be either a PID or a JID. The fg
 * job command resumes job by sending it a SIGCONT signal, and then runs it in
 * the foreground. The job argument can be either a PID or a JID
 *
 * @param tokens A pointer to a struct cmdline_tokens, which contains
 * information about the command and its arguments.
 *
 * @return The function does not have a return type specified, so it does not
 * explicitly return a value.
 */
void process_bg_fg_command(struct cmdline_tokens *tokens) {

    pid_t pid;
    jid_t jid;
    // error handling for input pid or job id
    if (tokens->argv[1] == NULL) {
        sio_printf("%s command requires PID or %%jobid argument\n",
                   tokens->argv[0]);
        return;
    }
    // check if the input is job id, job id start with %
    if (tokens->argv[1][0] == '%') {
        jid = atoi(&tokens->argv[1][1]);
        // check job id valid and exist
        if (jid > 0 && job_exists(jid)) {
            // get pid of the job id
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
        // get pid from the users
    } else if ((pid = atoi(&tokens->argv[1][0])) > 0 && job_from_pid(pid)) {
        // get jid of the pid
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
    // get the state of the background or foreground
    job_state state = tokens->builtin == BUILTIN_BG ? BG : FG;
    // sent SIGCONT signal
    kill(-pid, SIGCONT);
    // Set the state of the job
    job_set_state(jid, state);
    // if job is background job just outout the jid and pid
    if (state == BG) {
        sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
    } else {
        // otherwise wait until it exited
        sigset_t mask;
        sigemptyset(&mask);
        while (fg_job() > 0) {
            sigsuspend(&mask);
        }
    }
}

/**
 * @brief The function checks if the given command is a built-in command and
 * performs the corresponding action.
 *
 * @param tokens The `tokens` parameter is a pointer to a `struct
 * cmdline_tokens` object. This object contains information about the command
 * line tokens parsed by the shell. It includes fields such as `builtin` (which
 * represents the type of builtin command), `outfile` (which represents the
 * output file for the command
 *
 * @return True if it is a builtin command
 */
bool builtin_command(struct cmdline_tokens *tokens) {
    sigset_t mask, prev_mask;
    // initialize mask
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);
    // quit to exit the shell
    if (tokens->builtin == BUILTIN_QUIT) {

        exit(0);
    }
    // jobs to list the jobs
    if (tokens->builtin == BUILTIN_JOBS) {
        // block signal during the list jobs operations
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        // check if there is IO redirection

        if (tokens->outfile != NULL) {
            int fd;
            // open file and if it is not successful, output error message
            if ((fd = open(tokens->outfile, O_WRONLY | O_CREAT | O_TRUNC,
                           DEFFILEMODE)) < 0) {
                perror(tokens->outfile);

            } else {
                // list jobs to the specific file descriptor
                list_jobs(fd);
            }
            close(fd);

        } else {
            // list jobs to stdout
            list_jobs(STDOUT_FILENO);
        }

        sigprocmask(SIG_SETMASK, &prev_mask, NULL);

        return true;
    }

    // bg or fg command case
    if (tokens->builtin == BUILTIN_BG || tokens->builtin == BUILTIN_FG) {
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        // process bg or fg job command
        process_bg_fg_command(tokens);
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return true;
    }

    return false;
}

/**
 * @brief  The eval function evaluates a command line input, parses it, and
 * executes the command if it is not a built-in command. Support background and
 * forground jobs
 *
 * @param cmdline A string containing the command line input from the user.
 *
 */
void eval(const char *cmdline) {
    // parse result of the command
    // PARSELINE_FG = 4,    ///< Foreground job
    // PARSELINE_BG = 5,    ///< Background job
    // PARSELINE_EMPTY = 6, ///< Empty cmdline
    // PARSELINE_ERROR = 7, ///< Parse error
    parseline_return parse_result;
    // cmdline token
    struct cmdline_tokens token;
    // process id
    pid_t pid;
    sigset_t mask, prev_mask, wait_mask;

    // initialize the mask
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);
    // mask for sigsuspend
    sigemptyset(&wait_mask);

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }
    // state of the jobs, background or forground
    job_state state = parse_result == PARSELINE_BG ? BG : FG;

    // if it is not builtin command, block the signal , and create a children
    // process to execute the program the user input
    if (!builtin_command(&token)) {

        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        // create the child process,
        if ((pid = fork()) == 0) {
            // child process part
            // unblock the signal
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            // put the child in a new process group whose group ID is identical
            // to the child PID. This would ensure that there will be only one
            // process, your shell, in the foreground process group
            setpgid(pid, pid);
            // check redirection IO input file and output error message
            if (token.infile != NULL) {
                int fd;
                if ((fd = open(token.infile, O_RDONLY, DEFFILEMODE)) < 0) {

                    perror(token.infile);

                    exit(1);

                } else {
                    // redirection the fd
                    dup2(fd, STDIN_FILENO);
                }
                close(fd);
            }

            // check redirection IO output file and output error message
            if (token.outfile != NULL) {
                int fd;
                if ((fd = open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC,
                               DEFFILEMODE)) < 0) {

                    perror(token.outfile);
                    exit(1);

                } else {
                    // redirection the fd
                    dup2(fd, STDOUT_FILENO);
                }
            }
            // execute the program
            if (execve(token.argv[0], token.argv, environ) < 0) {
                perror(token.argv[0]);

                exit(1);
            }
        } else {
            // parent process part

            // Check whether it is background or foreground job
            if (parse_result == PARSELINE_FG) {
                // add job list wait until it finished
                add_job(pid, state, cmdline);

                while (fg_job() > 0) {

                    sigsuspend(&wait_mask);
                }

                sigprocmask(SIG_SETMASK, &prev_mask, NULL);

            } else {

                jid_t jid = add_job(pid, state, cmdline);
                // background job output it jid and pid to user.
                sio_printf("[%d] (%d) %s\n", jid, pid, cmdline);
                // after all operation, unblock signal in the parent process
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            }
        }
    }
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief The function `sigchld_handler` handles the SIGCHLD signal, which is
 * sent when a child process changes state, and reaping child processes
 *
 * @param sig The parameter `sig` is the signal number that triggered the signal
 * handler. In this case, the signal handler is for the `SIGCHLD` signal, which
 * is sent to the parent process when a child process terminates or stops.
 *
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    int status;
    pid_t pid;
    sigset_t mask, prev;

    sigfillset(&mask);
    // block signal during the reaping child processes
    sigprocmask(SIG_BLOCK, &mask, &prev);

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {

        jid_t jid = job_from_pid(pid);
        // if the child process exit normally, just delete the job from joblist
        if (WIFEXITED(status)) {
            delete_job(jid);
        }

        // if the job is terminated by signal SIGINT, output terminated message
        // and delete job from joblist
        if (WIFSIGNALED(status)) {

            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                       WTERMSIG(status));
            delete_job(jid);
        }
        // if the job is stop by signal SIGINT, output stopped message and
        // change the state job
        if (WIFSTOPPED(status)) {

            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                       WSTOPSIG(status));

            job_set_state(jid, ST);
        }
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief The function `sigint_handler` handles the SIGINT signal by sending it
 * to the foreground job's, terminated the job
 *
 * @param sig The parameter `sig` is the signal number that triggered the signal
 * handler. In this case, the signal handler is for the SIGINT signal, which is
 * typically sent to a process when the user presses Ctrl+C on the keyboard.
 *
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    jid_t jid;
    pid_t pid;

    sigset_t mask_all, prev;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev);
    if ((jid = fg_job()) > 0) {

        pid = job_get_pid(jid);

        kill(-pid, SIGINT);
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
    return;
}

/**
 * @brief The sigtstp_handler function sends a SIGTSTP signal to the stop
 * foreground job's process group.
 *
 * @param sig The parameter "sig" is the signal number that triggered the signal
 * handler. In this case, the signal handler is for the SIGTSTP signal.
 *
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
