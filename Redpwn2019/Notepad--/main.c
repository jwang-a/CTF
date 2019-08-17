#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PACKET_TYPE_CREATE  '0'
#define PACKET_TYPE_EDIT    '1'
#define PACKET_TYPE_LIST    '2'
#define PACKET_TYPE_DELETE  '3'
#define PACKET_TYPE_READ    '4'

#define MAX_NOTES           100
#define MAX_NOTE_NAME_SIZE  100
#define MAX_NOTE_SIZE       500

typedef unsigned short ushort;

typedef struct note
{
    int nameSize;
    int textSize;
    char name[MAX_NOTE_NAME_SIZE];
    char text[MAX_NOTE_SIZE];
} note;

int heapSize(note* notes, int numNotes)
{
    int ret = 0;
    for(int i = 0; i < numNotes; i++)
        ret += (notes + i)->textSize;
    return ret;
}

int find(note* notes, int numNotes, ushort nameSize, char* name)
{
    for(int i = 0; i < numNotes; i++)
    {
        if((notes + i)->nameSize != nameSize) continue;
        for(int j = 0; j < (notes + i)->nameSize + 1; j++)
        {
            if(j == nameSize)
            {
                return i;
            }
            if((notes + i)->name[j] != name[j]) break;
        }
    }
    return -1;
}

void writeAllNotesToHeap(void* heapBase, note* notes, int numNotes)
{
    int noteHeapLoc = 0;
    for(int i = 0; i < numNotes; i++)
    {
        memcpy(heapBase + noteHeapLoc, (notes + i)->text, (notes + i)->textSize);
        noteHeapLoc += (notes + i)->textSize;
    }
}

void writeHeapToNotes(void* heapBase, note* notes, int numNotes)
{
    int readInd = 0;
    for(int i = 0; i < numNotes; i++)
    {
        memcpy((notes + i)->text, heapBase + readInd, (notes + i)->textSize);
        readInd += (notes + i)->textSize;
    }
}

void printHeap(void* heapBase, note* notes, int numNotes)
{
    int len = heapSize(notes, numNotes);
    for(int i = 0; i < len; i++)
        printf("%c", *(char*)(heapBase + i) );
    printf("\n");
}

void receiveCreate(note* notes, int numNotes)
{
    if(numNotes >= MAX_NOTES)
    {
        printf("Max amount of notes reached\n");
        return;
    }
    ushort nameSize, textSize;
    char name[MAX_NOTE_NAME_SIZE], text[MAX_NOTE_SIZE];

    scanf("%hu%*c", &nameSize);
    if(nameSize > MAX_NOTE_NAME_SIZE)
    {
        printf("File name too large\n");
        return;
    }
    if(nameSize == 0)
    {
        printf("Enter nonempty name\n");
        return;
    }
    scanf("%[^\n]%*c", name);
    scanf("%hu%*c", &textSize);
    if(textSize > MAX_NOTE_SIZE)
    {
        printf("File size too high\n");
        return;
    }
    if(textSize == 0)
    {
        printf("Enter nonempty file\n");
        return;
    }
    scanf("%[^\n]%*c", text);
    (notes + numNotes)->nameSize = nameSize;
    (notes + numNotes)->textSize = textSize;
    for(int i = 0; i < nameSize; i++)
    {
        (notes + numNotes)->name[i] = name[i];
    }
    for(int i = 0; i < textSize; i++)
    {
        (notes + numNotes)->text[i] = text[i];
    }
}

void receiveEdit(void* heapBase, note* notes, int numNotes)
{
    ushort nameSize;
    char name[MAX_NOTE_NAME_SIZE];
    scanf("%hu%*c", &nameSize);
    if(nameSize > MAX_NOTE_NAME_SIZE)
    {
        printf("File name too large\n");
        return;
    }
    if(nameSize == 0)
    {
        printf("Enter nonempty name\n");
        return;
    }
    scanf("%[^\n]%*c", &name);

    int ind = find(notes, numNotes, nameSize, name);
    if(ind == -1)
        return;

    int heapEdit = 0;
    for(int i = 0; i < numNotes; i++)
    {
        if((notes + i)->nameSize != nameSize)
        {
            heapEdit += (notes + i)->textSize;
            continue;
        }
        for(int j = 0; j < (notes + i)->nameSize + 1; j++)
        {
            if(j == nameSize)
            {
                ushort potentialTextSize;
                scanf("%hu%*c", &potentialTextSize);
                (notes + i)->textSize = potentialTextSize;

                scanf("%[^\n]%*c", (notes + i)->text );
                memcpy(heapBase + heapEdit, (notes + i)->text, (notes + i)->textSize);
            }
            if((notes + i)->name[j] != name[j]) break;

        }
        heapEdit += (notes + i)->textSize;
    }
}

void receiveListNotes(note* notes, int numNotes)
{
    for(int i = 0; i < numNotes; i++)
    {
        printf( "%s: \n", (notes + i)->name);
        printf( "\t%s\n", (notes + i)->text);
    }
}

void receiveDelete(note* notes, int numNotes)
{
    ushort nameSize;
    char name[MAX_NOTE_NAME_SIZE];
    scanf("%hu%*c", &nameSize);
    if(nameSize > MAX_NOTE_NAME_SIZE)
    {
        printf("File name too large\n");
        return;
    }
    if(nameSize == 0)
    {
        printf("Enter nonempty string\n");
        return;
    }
    scanf("%[^\n]%*c", name);

    int ind = find(notes, numNotes, nameSize, name);
    if(ind == -1)
        return;
    for(int k = ind; k < numNotes - 1; k++)
    {
        *(notes + k) = *(notes + k + 1);
    }
    *(notes + numNotes - 1) = (note){ 0 };
}

void receiveRead(note* notes, int numNotes)
{
    ushort nameSize;
    char name[MAX_NOTE_NAME_SIZE];
    scanf("%hu%*c", &nameSize);
    if(nameSize > MAX_NOTE_NAME_SIZE)
    {
        printf("File name too large\n");
        return;
    }
    if(nameSize == 0)
    {
        printf("Enter nonempty string\n");
        return;
    }
    scanf("%[^\n]%*c", name);

    int ind = find(notes, numNotes, nameSize, name);
    if(ind == -1)
        return;
    printf( "%s\n", (notes + ind)->text);
}

int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    void* heapBase = calloc(MAX_NOTES, MAX_NOTE_SIZE);

    int numNotes = 0;
    note notes[MAX_NOTES];

    while(1)
    {
        char inputType;
        scanf("%c%*c", &inputType);
        switch(inputType)
        {
            case PACKET_TYPE_CREATE:
                receiveCreate(notes, numNotes);
                numNotes++;
                writeAllNotesToHeap(heapBase, notes, numNotes);
                break;
            case PACKET_TYPE_EDIT:
                receiveEdit(heapBase, notes, numNotes);
                break;
            case PACKET_TYPE_LIST:
                receiveListNotes(notes, numNotes);
                break;
            case PACKET_TYPE_DELETE:
                receiveDelete(notes, numNotes);
                numNotes--;
                writeAllNotesToHeap(heapBase, notes, numNotes);
                break;
            case PACKET_TYPE_READ:
                receiveRead(notes, numNotes);
                break;
            case '5':
                printHeap(heapBase, notes, numNotes);
                break;
            default:
                break;
        }
        writeHeapToNotes(heapBase, notes, numNotes);
    }
}
