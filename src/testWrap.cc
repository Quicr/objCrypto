
#include <cassert>

int callTheWrap( int a, int b );

int main( int argc, char* argv[]) {

  int r = callTheWrap(1,2);
  assert ( r == 3 );
  
  return 0;
}
