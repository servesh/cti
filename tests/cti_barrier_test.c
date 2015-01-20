/******************************************************************************\
 * cti_barrier_test.c - An example program which takes advantage of the Cray
 *			tools interface which will launch an application from the given
 *			argv, display information about the job, and hold it at the 
 *			startup barrier.
 *
 * Copyright 2011-2015 Cray Inc.	All Rights Reserved.
 *
 * Unpublished Proprietary Information.
 * This unpublished work is protected to trade secret, copyright and other laws.
 * Except as permitted by contract or express written permission of Cray Inc.,
 * no part of this work or its content may be used, reproduced or disclosed
 * in any form.
 *
 * $HeadURL$
 * $Date$
 * $Rev$
 * $Author$
 *
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>

#include "cray_tools_fe.h"
#include "cti_fe_common.h"

void
usage(char *name)
{
	fprintf(stdout, "USAGE: %s [LAUNCHER STRING]\n", name);
	fprintf(stdout, "Launch an application using the cti library\n");
	fprintf(stdout, "and print out information.\n");
	return;
}

int
main(int argc, char **argv)
{
	// values returned by the tool_frontend library.
	cti_app_id_t		myapp;
	int					rtn;
	
	if (argc < 2)
	{
		usage(argv[0]);
		assert(argc > 2);
		return 1;
	}
	
	/*
	 * cti_launchAppBarrier - Start an application using the application launcher
	 *                        with the provided argv array and have the launcher
	 *                        hold the application at its startup barrier for 
	 *                        MPI/SHMEM/UPC/CAF applications.
	 */
	myapp = cti_launchAppBarrier((const char * const *)&argv[1],-1,-1,NULL,NULL,NULL);
	if (myapp == 0)
	{
		fprintf(stderr, "Error: cti_launchAppBarrier failed!\n");
		fprintf(stderr, "CTI error: %s\n", cti_error_str());
	}
	assert(myapp != 0);
	
	// call the common FE tests
	cti_test_fe(myapp);
	
	printf("\nHit return to release the application from the startup barrier...");
	
	// just read a single character from stdin then release the app/exit
	(void)getchar();
	
	/*
	 * cti_releaseAppBarrier - Release the application launcher launched with the
	 *                         cti_launchAppBarrier function from its startup
	 *                         barrier.
	 */
	rtn = cti_releaseAppBarrier(myapp);
	if (rtn)
	{
		fprintf(stderr, "Error: cti_releaseAppBarrier failed!\n");
		fprintf(stderr, "CTI error: %s\n", cti_error_str());
		cti_killApp(myapp, SIGKILL);
	}
	assert(rtn == 0);
	
	/*
	 * cti_deregisterApp - Assists in cleaning up internal allocated memory
	 *                     associated with a previously registered application.
	 */
	cti_deregisterApp(myapp);
	
	// ensure deregister worked.
	assert(cti_appIsValid(myapp) == 0);
	
	return 0;
}

