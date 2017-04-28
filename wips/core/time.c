#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "main.h"

void freshTime()
{
	time((time_t*)&ctx.timeNow);
	return;
}

void setTimeNow(time_t* time)
{
	if(time == NULL)
		return ;
	memcpy(time,&ctx.timeNow,sizeof(time_t));
	return;
}
	
	
