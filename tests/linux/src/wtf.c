#include<unistd.h>
#include<stdlib.h>
int main(int c,char**v){
    int max=c>1?atoi(v[1]):6,n=0;
    void* p[16]={&&a,&&b,0,&&c,0,0,&&d,0,0,0,&&e,0,0,0,0,&&f};
L:  if(n<max)goto*p[n*(n+1)/2]; /* jump slots at triangular numbers */
    return 0;
a:write(1,"H",1);n++;goto L;
b:write(1,"E",1);n++;goto L;
c:write(1,"L",1);n++;goto L;
d:write(1,"L",1);n++;goto L;
e:write(1,"O",1);n++;goto L;
f:write(1,"!\n",2);n++;goto L;
  return 0;
}
