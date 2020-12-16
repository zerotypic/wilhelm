#include <stdio.h>
#include <stdlib.h>

extern "C" int a_function(int *a, int b) {
   printf("This is a function.\n");
   return *a + b;
}

typedef struct {
   int x;
   int y;
   char *str;
   void *next;
} a_struct;

extern "C" int take_a_struct(a_struct *s) {
   return s->x + s->y;
}

extern "C" int test_ast(int foo, int bar, char *duh, a_struct *structarg) {

   int baz, blah, ding;
   int *boing;
   char dong;
   float whee;
   a_struct stru;
   a_struct *ptr, *ptr2;

   stru.y = 82;                 /* AssignExpr, OffsetExpr, NumExpr */
   stru.x = structarg->y;       /* PtrOffsetExpr */
   *(stru.str) = dong;          /* DerefExpr */
   stru.str[3] = '\0';          /* IndexExpr */
   take_a_struct(&stru);        /* CallExpr, GlobalVarExpr, RefExpr */
   
   
 test:
   whee = (float) foo * 2.5;    /* BinOpExpr, CastExpr, FPNumExpr */
   printf("%f", whee);
   
   /* ForStmt, BlockStmt, UnaOpExpr, TernOpExpr */
   int i;   
   for (i = 0;
        (foo > 0) && (i < ((blah > 10) ? baz : 52));
        ++i) {    
      
      if (a_function(boing, foo)) { /* IfStmt */
         printf("foo\n");           /* StrExpr */
         break;                     /* BreakStmt */
      }

      ++blah;
      if (i > 5) {
         if (a_function(&foo, foo) != foo) {
            continue;        /* ContinueStmt */
         }
         printf("ding\n");
      } else {
         printf("dong\n");
      }
      printf("boing.\n");
   }

   while (a_function(boing, foo) != 3) { /* WhileStmt */
      bar++;
      if (a_function(boing, foo) != 2) {
         goto test;                /* GotoStmt */
      }
   }

   do {                         /* DoStmt */
      foo++;
   } while (a_function(boing, foo) > 10);

   switch (bar) {               /* SwitchStmt */
   case 0: printf("a0\n"); break;
   case 1: printf("b1\n"); break;
   case 2: printf("c2\n"); break;
   case 3: printf("d3\n"); break;
   case 4: printf("e4\n"); break;
   case 5: printf("f5\n"); break;
   case 6: printf("g6\n"); break;
   default: printf("ah\n");
   }

   return bar + foo;            /* ReturnStmt */

}

class TestClass {
public:

   TestClass(int x) {
      printf("constructor.");
   }

   void overloaded_func(int a, int b) {
      printf("%d\n", a+ b);
   }

   void overloaded_func(const char *x) {
      printf("%s", x);
   }

};

void test_foo() {
   TestClass obj(3);
   obj.overloaded_func(1, 2);
   obj.overloaded_func("a test");
}
