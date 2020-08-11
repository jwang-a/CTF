#ifndef VARIABLES_
#define VARIABLES_

#define ALLOCATE 0x01
#define DELETE   0x02
#define EDIT     0x03
#define PRINT    0x04
#define OPERATE  0x05
#define CONCAT   0x06

typedef struct SVALUE{
  char *value;
  size_t size;
}SVALUE;

typedef struct VARS{
  char *type;
  union VALUE{
    size_t iValue;
    SVALUE *sValue;
    char cValue;
  }value;
}VARS;

char *code;
int offset;
VARS *globalVar[0x100] = { 0, };
char *globalTypes[3] = { "INT", "STRING", "CHAR" /*, "POINTER" */ };

#endif