/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include <errno.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

#define MAX_FAIL_ATTEMPTS 5
#define MAX_PASSWD_AGE 3

typedef void (*sighandler_t)(int);

void sighandler(int signum, sighandler_t handler) {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
	if (signal(signum, handler) == SIG_ERR)
	{
		printf("Cannot ignore %d\n",signum);
		exit(0);
	}
}

int main(int argc, char *argv[]) {

	//struct passwd *passwddata; /* this has to be redefined in step 2 */
	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass, *crypt_pass;
	char *envp[]={0};

	//sighandler(SIGKILL, SIG_IGN);
	sighandler(SIGABRT, SIG_IGN);
	sighandler(SIGTERM, SIG_IGN);
	//sighandler(SIGSTOP, SIG_IGN);
	sighandler(SIGQUIT, SIG_IGN);
	sighandler(SIGINT, SIG_IGN);

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		//if (gets(user) == NULL) /* gets() is vulnerable to buffer */
		if (fgets(user, LENGTH, stdin) == NULL) 
			exit(0); 
		
		user[strcspn(user, "\n")] = 0;

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {

			crypt_pass = crypt(user_pass, passwddata->passwd_salt);

			if (!strcmp(crypt_pass, passwddata->passwd)) {

			printf("SNN_LOG: name: %s, UID: %d,Passwd: %s, Salt: %s, pwfailedCount : %d, Age: %d \n",\
				       	passwddata->pwname,\
				       	passwddata->uid, passwddata->passwd, \
					passwddata->passwd_salt, passwddata->pwfailed, passwddata->pwage);

				printf(" You're in !\n");
				printf ("Number of failed attempts: %d\n", passwddata->pwfailed);
				passwddata->pwfailed = 0;
				passwddata->pwage++;
				if (passwddata->pwage > MAX_PASSWD_AGE)
				{
					printf("Please change the password\n");
					user_pass = getpass(prompt);
					passwddata->passwd = crypt(user_pass, passwddata->passwd_salt);
					passwddata->pwage = 0;
				}
				mysetpwent(passwddata->pwname, passwddata);

				int ret = setuid(passwddata->uid);
			        if (ret != 0)	{
                                        printf("Failed to set uid returnVal %d errono %s\n", ret, strerror(errno));
                                        exit(0);
                                }

				execve("/bin/sh",argv,envp);
				perror("ERROR: Command line cannot be invoked\n");

			}
			else{
				passwddata->pwfailed++;
			       	printf("Login Incorrect, Failed attempt: %d \n ", passwddata->pwfailed);
				mysetpwent(passwddata->pwname, passwddata);
				if (passwddata->pwfailed > MAX_FAIL_ATTEMPTS) // Max fail attempts
					{
						printf("Too many login errors. Account locked!!!");
						exit(0);
					}
			}
		}
		else 
			       	printf("Login Incorrect !\n ");
	}
	return 0;
}
