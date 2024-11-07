#include "icmp.h"

unsigned short
icmp_cksum (unsigned char *addr, int len)
{
  int sum = 0;
  unsigned short answer = 0;
  unsigned short *wp;

  for (wp = (unsigned short *) addr; len > 1; wp++, len -= 2)
    sum += *wp;

  /* Take in an odd byte if present */
  if (len == 1)
    {
      *(unsigned char *) &answer = *(unsigned char *) wp;
      sum += answer;
    }

  sum = (sum >> 16) + (sum & 0xffff);	/* add high 16 to low 16 */
  sum += (sum >> 16);		/* add carry */
  answer = ~sum;		/* truncate to 16 bits */
  return answer;
}