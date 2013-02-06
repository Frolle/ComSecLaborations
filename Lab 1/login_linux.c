/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
 #include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define PWAGE 4
#define PW_TRIES 3

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGSTOP, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);	
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	char *my_envp[] = { NULL };
	char *my_argv[] = { NULL };


	sighandler();

	while (TRUE) {
		printf("\n\n");
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */
		int i;
		for(i=0; i<LENGTH;i++){
		  if(user[i]=='\n')
		    user[i]='\0';
		}
		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);
		if(passwddata == NULL) {
			printf("Cannot find that user\n");
			continue;
		}
		user_pass = crypt(user_pass, passwddata->passwd_salt);
		if(user_pass == NULL)
		{
			printf("Error in hashing your password");
			continue;
		}

		//printf("User input: %s\nFrom db: %s\n", user_pass, passwddata->passwd);

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			int answer = 42;
			int userinput;
			if(passwddata->pwfailed >= PW_TRIES){
			 	printf("Human test, answer this question: What's 6*7?\n");
				scanf("%d", &userinput);
				if(userinput!=answer){
					printf("WRONG ANSWER! YOU'RE SKYNET!\n");
					exit(0);
				}
				else
					printf("YOU'RE HUMAN! AWESOME!\n");
			}
		      
			if (!strcmp(user_pass, passwddata->passwd)) {

				printf(" You're in !\n");
				printf("Number of failed attempts: %d\n", passwddata->pwfailed);
				passwddata->pwfailed = 0;
				passwddata->pwage++;

				if(passwddata->pwage >= PWAGE)
				  printf("Your password is old, change it.\n");
				if(mysetpwent(user, passwddata)==-1){
					printf("Coudln't access the database");
					continue;
				}
				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */
				if(setuid(passwddata->uid) != 0)
				{
					printf("Cannot set user id\n");
					continue;
				}
				if(execve("/bin/sh", my_argv, my_envp) == -1)
				{
					printf("Cannot start shell\n");
					continue;
				}

			}
			else{
				passwddata->pwfailed++;
				if(mysetpwent(user, passwddata)==-1){
					printf("Couldn't access the database");
					continue;
				}
				printf("Login Incorrect \n");
			}
		}
	}
	return 0;
}

