#include <support.h>
const U2 record_layouts[]={2,3,Z,};
static X c0;
static X p0,p1;
static X f1(X x0,X x1){return s79(x1);}
static X f2(X x0,X x1){return s18(x1);}
int main(int argc,const char*argv[]){
static _Alignas(16) char heap_bytes[256*1024*1024];s36(sizeof(heap_bytes),heap_bytes,1024*1024,sizeof(record_layouts)/sizeof(record_layouts[0]),record_layouts,argc,argv);
c0=({const char s[]="Hello!";s86(sizeof(s)-1,s);});
p0=({X x0,x1;x0=s75(f2,1,0,0);x1=s75(f1,1,0,0);s30(2,(X[]){x0,x1},0);});
p1=({X x0;x0=p0;({X c=s31(x0,3);((X(*)(X,X))s35(c,1))(c,c0);});});
return 0;}
