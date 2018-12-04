# Return oriented programming at its simplest form.

`rop.c binary`

`#include <string.h>

#include <unistd.h>

int main (int argc, char **argv){
  char buf [1024];
  
  if(argc == 2){
    strcpy(buf, argv[1]);
  } else {
    system("/usr/bin/false");
  }
}
`
