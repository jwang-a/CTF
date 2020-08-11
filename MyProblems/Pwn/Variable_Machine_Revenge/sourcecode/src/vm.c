#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../includes/vm.h"
#include "../includes/variables.h"
#include "../includes/gc.h"

extern char* strdup(const char*);

int initVm(char *c, int length) {
    for(int i=0; i<length; i++){
        // check error
        // if (err) return 1;
    }
    code = c;
    offset = 0;

    return 0; 
}

size_t fetch() {
    size_t res = 0;
    int command = code[offset++];
    #ifdef DEBUG   
        printf("fetch() command : %d\n", command);
    #endif
    SETOPCODE(res, command);
    switch (command) {
        case DELETE:
        case PRINT: 
            #ifdef DEBUG   
                printf("fetch() arg1 : %d\n", code[offset]);
            #endif
            SETARG1(res, code[offset++]);
            
            break;

        case EDIT:  
            #ifdef DEBUG   
                printf("fetch() arg1 : %d\n", code[offset]);
            #endif
            SETARG1(res, code[offset++]);
            #ifdef DEBUG   
                printf("fetch() arg2 : %d\n", code[offset]);
            #endif
            SETARG2(res, code[offset++]);
            
            break;

        case ALLOCATE:
        case OPERATE:
        case CONCAT:
            #ifdef DEBUG   
                printf("fetch() arg1 : %d\n", code[offset]);
            #endif
            SETARG1(res, code[offset++]);
            #ifdef DEBUG   
                printf("fetch() arg2 : %d\n", code[offset]);
            #endif
            SETARG2(res, code[offset++]);
            #ifdef DEBUG   
                printf("fetch() arg3 : %d\n", code[offset]);
            #endif
            SETARG3(res, code[offset++]);
            
            break;

        default:
            return 0;
    }
    #ifdef DEBUG
        printf("fetch() : 0x%08zx\n", res);
    #endif
    return res; 
}

int allocate(size_t opcode){
    int idx = GETARG1(opcode);

    if(globalVar[idx]) return 0; 

    globalVar[idx] = (VARS*)gcCalloc(1, sizeof(VARS));
    globalVar[idx]->type = globalTypes[GETARG2(opcode) % 3];

    if(!strcmp(globalVar[idx]->type, "INT")){
        #ifdef DEBUG
            printf("allocate() arg3 : %lu\n", GETARG3(opcode));
        #endif
        globalVar[idx]->value.iValue = GETARG3(opcode);
    }else if(!strcmp(globalVar[idx]->type, "STRING")){
        globalVar[idx]->value.sValue = (SVALUE *)gcCalloc(1, sizeof(SVALUE));
        globalVar[idx]->value.sValue->size = GETARG3(opcode);
        globalVar[idx]->value.sValue->value = (char *)gcCalloc(GETARG3(opcode), 1);
    }else if(!strcmp(globalVar[idx]->type, "CHAR")){
        globalVar[idx]->value.cValue = GETARG3(opcode);
    }else {
        return 0;
    }

    return 1;
}

int delete(size_t opcode){
    int idx = GETARG1(opcode);

    if(!globalVar[idx]) return 0;

    if(!strcmp(globalVar[idx]->type, "STRING")) gcFree(globalVar[idx]->value.sValue);
    gcFree(globalVar[idx]);
    globalVar[idx] = 0;

    return 1;
}

int edit(size_t opcode){
    int idx = GETARG1(opcode);

    if(!globalVar[idx]) return 0;

    if(!strcmp(globalVar[idx]->type, "INT")){
        globalVar[idx]->value.iValue = GETARG2(opcode);
    }else if(!strcmp(globalVar[idx]->type, "STRING")){
        if(GETARG2(opcode) > globalVar[idx]->value.sValue->size) return 0;
        for(int i=0; i<GETARG2(opcode); i++) globalVar[idx]->value.sValue->value[i] = getchar();
    }else if(!strcmp(globalVar[idx]->type, "CHAR")){
        globalVar[idx]->value.cValue = GETARG2(opcode);
    }
    return 1;
}

int print(size_t opcode){
    int idx = GETARG1(opcode);

    if(!globalVar[idx]) return 0;

    if(!strcmp(globalVar[idx]->type, "INT")){
        printf("[INT %d : %zu]\n", idx, globalVar[idx]->value.iValue);
    }else if(!strcmp(globalVar[idx]->type, "STRING")){
        printf("[STRING %d : %s]\n", idx, globalVar[idx]->value.sValue->value);
    }else if(!strcmp(globalVar[idx]->type, "CHAR")){
        printf("[CHAR %d : %c]\n", idx, globalVar[idx]->value.cValue);
    }
    return 1;
}

int operate(size_t opcode){
    int operater = GETARG1(opcode);
    int idx1 = GETARG2(opcode);
    int idx2 = GETARG3(opcode);

    if(!globalVar[idx1]) return 0;
    if(!globalVar[idx2]) return 0;

    if(strcmp(globalVar[idx1]->type, "INT") || strcmp(globalVar[idx2]->type, "INT")) return 0;

    size_t tmp;

    if(operater == 1) tmp = globalVar[idx1]->value.iValue + globalVar[idx2]->value.iValue;
    else if(operater == 2) tmp = globalVar[idx1]->value.iValue - globalVar[idx2]->value.iValue;
    else if(operater == 3) tmp = globalVar[idx1]->value.iValue * globalVar[idx2]->value.iValue;
    else if(operater == 4) tmp = globalVar[idx2]->value.iValue == 0 ? globalVar[idx1]->value.iValue : globalVar[idx1]->value.iValue / globalVar[idx2]->value.iValue;

    globalVar[idx1]->value.iValue = tmp;
    
    return 1;
}

int concat(size_t opcode){
    int type = GETARG1(opcode);
    int idx1 = GETARG2(opcode);
    int idx2 = GETARG3(opcode);

    if(!globalVar[idx1]) return 0;
    if(!globalVar[idx2]) return 0;

    if(type == 1){
        if(strcmp(globalVar[idx1]->type, "CHAR") || strcmp(globalVar[idx2]->type, "CHAR")) return 0;

        char tmp1 = globalVar[idx1]->value.cValue;
        char tmp2 = globalVar[idx2]->value.cValue;

        char tmp[3];
        snprintf(tmp, sizeof(tmp), "%c%c", tmp1, tmp2);

        globalVar[idx1]->type = "STRING";
        globalVar[idx1]->value.sValue = (SVALUE *)gcCalloc(1, sizeof(SVALUE));
        globalVar[idx1]->value.sValue->size = strlen(tmp);
        globalVar[idx1]->value.sValue->value = (char *)strdup(tmp);
    } else if (type == 2){
        #ifdef DEBUG
            printf("Type1 : %s\n", globalVar[idx1]->type);
            printf("Type2 : %s\n", globalVar[idx2]->type);
        #endif
        if(strcmp(globalVar[idx1]->type, "STRING") || strcmp(globalVar[idx2]->type, "STRING")) return 0;

        SVALUE *tmp1 = globalVar[idx1]->value.sValue;
        SVALUE *tmp2 = globalVar[idx2]->value.sValue;

        char *tmp = (char *)gcCalloc(tmp1->size + tmp2->size + 1, 1);
        snprintf(tmp, tmp1->size + tmp2->size + 1, "%s%s", tmp1->value, tmp2->value);
        gcFree(globalVar[idx1]->value.sValue->value);
        globalVar[idx1]->value.sValue->size = strlen(tmp);
        globalVar[idx1]->value.sValue->value = tmp;
    } else {
        return 0;
    }
    return 1;
}

int execute(size_t opcode) {
    switch (GETOPCODE(opcode)) {
        case ALLOCATE:
            if(allocate(opcode) == 0) return 0; 
            break;
        case DELETE:
            if(delete(opcode) == 0) return 0; 
            break;
        case EDIT:
            if(edit(opcode) == 0) return 0; 
            break;
        case PRINT:
            if(print(opcode) == 0) return 0; 
            break;
        case OPERATE:
            if(operate(opcode) == 0) return 0; 
            break;
        case CONCAT:
            if(concat(opcode) == 0) return 0; 
            break;
        default:
            return 0; 
    }
    return 1;
}