import gdb

class PrintTree(gdb.Command):
    def __init__(self):
        super(PrintTree,self).__init__("printtree",gdb.COMMAND_USER)

    def parsenode(self,node):
        value,left,right = gdb.execute(f'x/3wx {node}',to_string=True).split('\t0x')[1:]
        return int(left,16),int(right,16),int(value,16)

    def printnode(self,value,path):
        prefix = '+------'
        path = path[::-1]
        for i in range(1,len(path)):
            if path[i]==path[i-1] or i==len(path)-1:
                prefix = '        '+prefix
            else:
                prefix = '|       '+prefix
        print(prefix,end='(')
        if value==0x19:
            print(f'\033[0;31m{value}\033[0m',end=')\n')
        else:
            print(f'{value}',end=')\n')

    def printtree(self,root,path):
        if root==0:
            return
        left,right,value = self.parsenode(root)
        self.printtree(left,path+['L'])
        self.printnode(value,path)
        self.printtree(right,path+['R'])

    def invoke(self,args,from_tty):
        rootnode = int(gdb.execute(f'x/wx {ROOT}',to_string=True).split('\t0x')[-1],16)
        print('=====TREE=====')
        self.printtree(rootnode,['N'])
        print('')
        print('==============')

def main():
    PrintTree()
    gdb.execute('file accounting_patched')
    gdb.execute('b main')
    gdb.execute('run')
    global PID,PSTDIN,PSTDOUT
    PID = gdb.selected_inferior().pid
    PSTDIN = open(f'/proc/{PID}/fd/0','w')
    PSTDOUT = open(f'/proc/{PID}/fd/1','r')
    global ROOT
    ENVIRON = int(gdb.execute('x/wx &environ',to_string=True).split('\t0x')[-1],16)
    ROOT = ENVIRON-0x1f8
    gdb.execute('d 1')
    gdb.execute('b *0x8049110')
    for i in range(5):
        gdb.execute('c')
        gdb.execute('printtree')

main()
