# EmojiiVM (misc)

## Problem Overcap
This is a EmojiLang PPM challange!!  

We are required to create an EmojiLang script that outputs the 9x9 multiplication table (exact output given in answer.txt)  

Additionally, the script should have length < 0x2000 and will not take any input (smart move, else I could write a script that takes input and prints it XDD)

## Solution
The length limit is quite large, and as long as you implement a for loop to do this job, my solution is something like this

```
//Note that if statement automatically pops the True/False condition from stack in the pseudo code below
//printstack also clears the entire stack

//Initialize constant symbols and arg1, arg2
Storage[0] = ['*','=',' ','','']
Storage[1] = [1]
Storage[2] = [1]

START_LOOP:
	stackpush('\n')

	//calculate arg1*arg2
	Storage[0][3] = Storage[1]*Storage[2]

	//prepare carry, and modify values for printing
	Storage[0][4] = 0
	CARRY:
		stackpush(9<Storage[0][3])
		Storage[0][3]-=10
		Storage[0][4]+=1
		if stacktop is True:
			goto CARRY
	stackpush(Storage[0][3]+'0'-10)
	Storage[0][3] = (Storage[0][4]==1)
	stackpush(Storage[0][4]+'0'+1)
	stackpush(Storage[0][3])
	if stacktop is False:
		goto CARRY_EXIST
	stackpop

CARRY_EXIST:
	//prepare expression for printing
	stackpush(Storage[0][2])
	stackpush(Storage[0][1])
	stackpush(Storage[0][2])
	stackpush(Storage[2][0]+'0')
	stackpush(Storage[0][2])
	stackpush(Storage[0][0])
	stackpush(Storage[0][2])
	stackpush(Storage[1][0]+'0')
	printstack()

	//modify arg1, arg2 and check if quit
	stackpush(Storage[2][0]+1==10)
	if stacktop is False:
		goto INCREASE_ARG2
	Storage[2][0] = 1
	Storage[1][0]+=1
	stackpush(Storage[1][0]==10)
	if stacktop is False:
		goto START_LOOP
	exit()
INCREASE_ARG2:
	Storage[2][0]+=1
	goto START_LOOP
```
