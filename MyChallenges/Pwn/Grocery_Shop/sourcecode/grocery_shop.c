/*gcc -Wl,-z,now -fpie -fstack-protector-all grocery.c -o grocery*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"SECCOMP.h"

#define BLACK 0
#define RED 1

struct sock_filter seccompfilter[]={
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ArchField),
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SyscallNum),
  Allow(read),
  Allow(write),
  Allow(open),
  Allow(mprotect),
  Allow(rt_sigreturn),
  Allow(brk),
  Allow(exit),
  Allow(exit_group),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog filterprog={
  .len=sizeof(seccompfilter)/sizeof(struct sock_filter),
  .filter=seccompfilter
};

typedef struct Item{
  double value;
  char *name;
}ITEM;

typedef struct Node{
  struct Node *parent,*left,*right;
  unsigned char color;
  ITEM *item;
}NODE;

void apply_seccomp(){
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)){
    perror("Seccomp Error");
    exit(1);
  }
  if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filterprog)==-1){
    perror("Seccomp Error");
    exit(1);
  }
  return;
}

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  apply_seccomp();
  return;
}

void printerror(char *msg){
  puts(msg);
  exit(1);
}

ITEM* newitem(double value,char* name){
  ITEM *item=malloc(sizeof(ITEM));
  item->value = value;
  item->name = strdup(name);
  return item;
}

NODE* newnode(ITEM *item){
  NODE *node = malloc(sizeof(NODE));
  node->parent = NULL;
  node->left = NULL;
  node->right = NULL;
  node->color = RED;
  node->item = item;
  return node;
}

int comparevalue(NODE *n1,NODE *n2){
  if(n1->item->value==n2->item->value)
    return 0;
  else if(n1->item->value>n2->item->value)
    return 1;
  else
    return -1;
}

int comparename(NODE *n1,NODE *n2){
  return strcmp(n1->item->name,n2->item->name);
}

void leftrotate(NODE **root,NODE *pivot){
  NODE *right = pivot->right;
  pivot->right = right->left;
  if(pivot->right!=NULL)
    pivot->right->parent = pivot;
  right->parent = pivot->parent;
  if(right->parent==NULL)
    *root = right;
  else if(right->parent->left==pivot)
    right->parent->left = right;
  else
    right->parent->right = right;
  right->left = pivot;
  pivot->parent = right;
  return;
}

void rightrotate(NODE **root,NODE *pivot){
  NODE *left = pivot->left;
  pivot->left = left->right;
  if(pivot->left!=NULL)
    pivot->left->parent = pivot;
  left->parent = pivot->parent;
  if(left->parent==NULL)
    *root = left;
  else if(left->parent->left==pivot)
    left->parent->left = left;
  else
    left->parent->right = left;
  left->right = pivot;
  pivot->parent = left;
  return;
}

void insertnode(NODE **root,NODE *node,int (*cmp)(NODE*,NODE*)){
  if(*root==NULL){
    *root = node;
    node->color = BLACK;
    return;
  }
  NODE *cur = *root;
  while(cur!=NULL){
    if(cmp(node,cur)>0){
      if(cur->right==NULL){
        cur->right = node;
	node->parent = cur;
	break;
      }
      else
        cur = cur->right;
    }
    else{
      if(cur->left==NULL){
        cur->left = node;
	node->parent = cur;
	break;
      }
      else
        cur = cur->left;
    }
  }
  while(node!=*root&&node->parent->color==RED){
    if(node->parent==node->parent->parent->left){
      cur = node->parent->parent->right;
      if(cur!=NULL&&cur->color==RED){
        node->parent->color = BLACK;
	cur->color = BLACK;
	cur->parent->color = RED;
	node = cur->parent;
      }
      else{
        if(node->parent->right==node){
          node = node->parent;
          leftrotate(root,node);
        }
        node->parent->color = BLACK;
        node->parent->parent->color = RED;
        rightrotate(root,node->parent->parent);
	break;
      }
    }
    else{
      cur = node->parent->parent->left;
      if(cur!=NULL&&cur->color==RED){
        node->parent->color = BLACK;
	cur->color = BLACK;
	cur->parent->color = RED;
	node = cur->parent;
      }
      else{
        if(node->parent->left==node){
          node = node->parent;
	  rightrotate(root,node);
        }
        node->parent->color = BLACK;
        node->parent->parent->color = RED;
        leftrotate(root,node->parent->parent);
	break;
      }
    }
    if(node==*root)
      node->color = BLACK;
  }
  return;
}

void removenode(NODE **root,NODE *node){
  NODE *cur, *fixup;
  NODE NIL;
  NIL.parent = NULL;
  char color;
  while(1){
    color = node->color;
    if(node->left==NULL||node->right==NULL){
      if(node->left==NULL)
        fixup = node->right;
      else if(node->right==NULL)
        fixup = node->left;
      if(fixup==NULL){
        fixup = &NIL;
        fixup->right = NULL;
        fixup->left = NULL;
        fixup->color = BLACK;
      }
      if(node->parent==NULL){
        if(fixup==&NIL){
          *root = NULL;
	  return;
        }
        else
          *root = fixup;
      }
      else if(node==node->parent->left)
        node->parent->left = fixup;
      else
        node->parent->right = fixup;
      fixup->parent = node->parent;
      break;
    }
    else{
      cur = node->right;
      while(cur->left!=NULL)
        cur = cur->left;
      if(cur==node->right){
        cur->parent = node->parent;
	if(node->parent==NULL)
          *root = cur;
        else if(node==node->parent->left)
          node->parent->left = cur;
        else
          node->parent->right = cur;
        node->parent = cur;
	cur->left = node->left;
	cur->left->parent = cur;
	node->left = NULL;
	node->right = cur->right;
	if(cur->right!=NULL)
          cur->right->parent = node;
	cur->right = node;
      }
      else{
        fixup = cur->parent;
	cur->parent = node->parent;
	if(node->parent==NULL)
          *root = cur;
        else if(node==node->parent->left)
          node->parent->left = cur;
        else
          node->parent->right = cur;
	node->parent = fixup;
	if(fixup->left==cur)
          fixup->left = node;
	else
          fixup->right = node;
	cur->left = node->left;
	cur->left->parent = cur;
	fixup = cur->right;
	cur->right = node->right;
	cur->right->parent = cur;
	node->left = NULL;
	node->right = fixup;
	if(fixup!=NULL)
          fixup->parent = node;
      }
      node->color = cur->color;
      cur->color = color;
    }
  }
  if(color==RED){
    if(NIL.parent!=NULL){
      if(NIL.parent->left==&NIL)
        NIL.parent->left = NULL;
      else
        NIL.parent->right = NULL;
    }
    return;
  }
  if(fixup==*root||fixup->color==RED){
    if(NIL.parent!=NULL){
      if(NIL.parent->left==&NIL)
        NIL.parent->left = NULL;
      else
        NIL.parent->right = NULL;
    }
    fixup->color = BLACK;
    return;
  }
  while(fixup!=*root&&fixup->color!=RED){
    if(fixup==fixup->parent->left){
      cur = fixup->parent->right;
      if(cur->color==RED){
        cur->color = BLACK;
	cur->parent->color = RED;
	leftrotate(root,fixup->parent);
	cur = fixup->parent->right;
      }
      if((cur->left==NULL||cur->left->color==BLACK)&&(cur->right==NULL||cur->right->color==BLACK)){
        cur->color = RED;
	fixup = fixup->parent;
      }
      else{
        if(cur->right==NULL||cur->right->color==BLACK){
          cur->color = RED;
	  cur->left->color = BLACK;
	  rightrotate(root,cur);
	  cur = fixup->parent->right;
        }
        cur->color = cur->parent->color;
        cur->parent->color = BLACK;
        if(cur->right!=NULL)
          cur->right->color = BLACK;
	leftrotate(root,cur->parent);
	break;
      }
    }
    else{
      cur = fixup->parent->left;
      if(cur->color==RED){
        cur->color = BLACK;
	cur->parent->color = RED;
	rightrotate(root,fixup->parent);
	cur = fixup->parent->left;
      }
      if((cur->right==NULL||cur->right->color==BLACK)&&(cur->left==NULL||cur->left->color==BLACK)){
        cur->color = RED;
	fixup = fixup->parent;
      }
      else{
	if(cur->left==NULL||cur->left->color==BLACK){
          cur->color = RED;
	  cur->right->color = BLACK;
	  leftrotate(root,cur);
	  cur = fixup->parent->left;
        }
        cur->color = cur->parent->color;
	cur->parent->color = BLACK;
	if(cur->left!=NULL)
          cur->left->color = BLACK;
	rightrotate(root,cur->parent);
	break;
      }
    }
    if(fixup==*root||fixup->color==RED){
      fixup->color = BLACK;
      break;
    }
  }
  if(NIL.parent!=NULL){
    if(NIL.parent->left==&NIL)
      NIL.parent->left = NULL;
    else
      NIL.parent->right = NULL;
  }
  return;
}

NODE *searchnode(NODE *cur,NODE *target,int (*cmp)(NODE*,NODE*)){
  while(cur!=NULL){
    if(cmp(target,cur)==0)
      return cur;
    else if(cmp(target,cur)>0)
      cur = cur->right;
    else
      cur = cur->left;
  }
  return NULL;
}

void printitem(ITEM *item){
  printf("merchandise : %s, value : %f\n",item->name,item->value);
  return;
}

int submenu(){
  puts("============================");
  puts("|           menu           |");
  puts("============================");
  puts("| 1. Select by value       |");
  puts("| 2. Select by name        |");
  puts("============================");
  int choice=-1;
  printf("choice : ");
  if(scanf("%d",&choice)!=1)
    printerror("scanf error");
  return choice;
}

void addmerch(NODE **valueroot,NODE **nameroot){
  double value;
  char name[0x100];
  memset(name,0,0x100);
  printf("Merchandise value : ");
  if(scanf("%lf",&value)!=1)
    printerror("scanf error");
  printf("Merchandise name : ");
  if(scanf("%255s",name)!=1)
    printerror("scanf error");
  ITEM *item = newitem(value,name);
  NODE *node = newnode(item);
  if(searchnode(*valueroot,node,comparevalue)!=NULL||searchnode(*nameroot,node,comparename)!=NULL){
    puts("Cannot add merchandise with duplicate value/name");
    free(item->name);
    free(item);
    free(node);
  }
  else{
    insertnode(valueroot,node,comparevalue);
    NODE *node2 = newnode(item);
    insertnode(nameroot,node2,comparename);
  }
  return;
}

void removemerch(NODE **valueroot,NODE **nameroot){
  double value;
  char name[0x100];
  ITEM item;
  NODE node;
  NODE *valuenode, *namenode;
  switch(submenu()){
    case 1:
      printf("Merchandise value : ");
      if(scanf("%lf",&value)!=1)
        printerror("scanf error");
      item.value = value;
      node.item = &item;
      valuenode = searchnode(*valueroot,&node,comparevalue);
      if(valuenode==NULL)
        puts("Merchandise not found");
      else{
	namenode = searchnode(*nameroot,valuenode,comparename);
        removenode(valueroot,valuenode);
	free(valuenode);
	removenode(nameroot,namenode);
	free(namenode->item->name);
	free(namenode->item);
	free(namenode);
      }
      break;
    case 2:
      memset(name,0,0x100);
      printf("Merchandise name : ");
      if(scanf("%255s",name)!=1)
        printerror("scanf error");
      item.name = name;
      node.item = &item;
      namenode = searchnode(*nameroot,&node,comparename);
      if(namenode==NULL)
        puts("Merchandise not found");
      else{
	valuenode = searchnode(*valueroot,namenode,comparevalue);
        removenode(nameroot,namenode);
	free(namenode);
	removenode(valueroot,valuenode);
	free(valuenode->item->name);
	free(valuenode->item);
	free(valuenode);
      }
      break;
    default:
      puts("Invalid choice");
      break;
  }
  return;
}

void showmerch(NODE *valueroot,NODE *nameroot){
  double value;
  char name[0x100];
  ITEM item;
  NODE node;
  NODE *targetnode;
  switch(submenu()){
    case 1:
      printf("Merchandise value : ");
      if(scanf("%lf",&value)!=1)
        printerror("scanf error");
      item.value = value;
      node.item = &item;
      targetnode = searchnode(valueroot,&node,comparevalue);
      if(targetnode==NULL)
        puts("Merchandise not found");
      else
        printitem(targetnode->item);
      break;
    case 2:
      memset(name,0,0x100);
      printf("Merchandise name : ");
      if(scanf("%255s",name)!=1)
        printerror("scanf error");
      item.name = name;
      node.item = &item;
      targetnode = searchnode(nameroot,&node,comparename);
      if(targetnode==NULL)
        puts("Merchandise not found");
      else
        printitem(targetnode->item);
      break;
    default:
      puts("Invalid choice");
      break;
  }
  return;
}

int menu(){
  puts("============================");
  puts("|           menu           |");
  puts("============================");
  puts("| 1. Add merchandise       |");
  puts("| 2. Remove merchandise    |");
  puts("| 3. Find mercahndise      |");
  puts("| 4. Shut down             |");
  puts("============================");
  int choice;
  printf("choice : ");
  if(scanf("%d",&choice)!=1)
    printerror("scanf error");
  return choice;
}

int main(){
  initproc();
  NODE *valueroot=NULL,*nameroot=NULL;
  while(1){
    switch(menu()){
      case 1:
        addmerch(&valueroot,&nameroot);
        break;
      case 2:
	removemerch(&valueroot,&nameroot);
	break;
      case 3:
	showmerch(valueroot,nameroot);
	break;
      case 4:
	puts("Too bad :(");
        exit(0);
      default:
	puts("Invalid option");
	break;
    }
  }
  return 0;
}
