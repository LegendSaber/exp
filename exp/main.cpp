#include "CVE-2014-4113.h"
#include "CVE-2015-2546.h"
#include "CVE-2015-0057.h"

#define VUL_NAME "CVE-2015-2546"

int main()
{
	if (strcmp(VUL_NAME, "CVE-2014-4113") == 0)
	{
		if (Exploit_CVE_2014_4113())
		{
			printf("Exploit CVE_2015_2546 完成...\n");
			system("whoami");
		}
	}
	else if (strcmp(VUL_NAME, "CVE-2015-2546") == 0)
	{
		if (Exploit_CVE_2015_2546())
		{
			printf("Exploit CVE_2015_2546 完成...\n");
			system("whoami");
		}
	}
	else if (strcmp(VUL_NAME, "CVE-2015-0057") == 0)
	{

	}

	
	system("pause");

	return 0;
}