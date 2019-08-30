from pwn import *

class IO_FILE_plus(object):
    def __init__(self,arch=64):
        '''
        struct _IO_FILE_plus{
            struct _IO_FiLE{
                int _flags;
                char *_IO_read_ptr;
                char *_IO_read_end;
                char *_IO_read_base;
                char *_IO_write_base;
                char *_IO_write_ptr;
                char *_IO_write_end;
                char *_IO_buf_base;
                char *_IO_buf_end;

                char *_IO_save_base;
                char *_IO_backup_base;
                char *_IO_save_end;

                struct _IO_marker *markers;
                struct _IO_FILE *chain;

                int _fileno;
                int _flags2;
                _off_t _old_offset;
                unsigned short _cur_column;
                signed char _vtable_offset;
                char _shortbuf[1];
                IO_lock_t *_lock;

                _off64_t offset;
                struct _IO_codevt *_codecvt;
                struct _IO_wide_data * _wide_data;
                struct _IO_FILE *_freeres_list;
                void *_freeres_buf;
                size_t __pad5;
                int _mode;
                char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
            };
            strcut _IO_jump_t *vtable;
        };

	Flag:
		_IO_MAGIC         0xFBAD0000 Magic number
		_IO_MAGIC_MASK    0xFFFF0000
		_IO_USER_BUF          0x0001 Don't deallocate buffer on close
		_IO_UNBUFFERED        0x0002
		_IO_NO_READS          0x0004 Reading not allowed
		_IO_NO_WRITES         0x0008 Writing not allowed
		_IO_EOF_SEEN          0x0010
		_IO_ERR_SEEN          0x0020
		_IO_DELETE_DONT_CLOSE 0x0040 Don't call close(_fileno) on close
		_IO_LINKED            0x0080 In the list of all open files.
		_IO_IN_BACKUP         0x0100
		_IO_LINE_BUF          0x0200
		_IO_TIED_PUT_GET      0x0400 Put and get pointer move in unison
		_IO_CURRENTLY_PUTTING 0x0800
		_IO_IS_APPENDING      0x1000
		_IO_IS_FILEBUF        0x2000
				      0x4000 No longer used, reserved for compatability
		_IO_USER_LOCK         0x8000
        '''
        self.arch=arch
    def construct(self,flags=0,read_ptr=0,read_end=0,read_base=0,write_base=0,write_ptr=0,write_end=0,buf_base=0,buf_end=0,save_base=0,backup_base=0,save_end=0,markers=0,chain=0,fileno=0,flags2=0,old_offset=0,cur_column=0,vtable_offset=0,shortbuf=0,lock=0,offset=0,codecvt=0,wide_data=0,freeres_list=0,freeres_buf=0,pad5=0,mode=0,unused2=b'\x00'*20,vtable=0):
        if self.arch==32:
            return p32(flags)+p32(read_ptr)+p32(read_end)+p32(read_base)+p32(write_base)+p32(write_ptr)+p32(write_end)+p32(buf_base)+p32(buf_end)+p32(save_base)+p32(backup_base)+p32(save_end)+p32(markers)+p32(chain)+p32(fileno)+p32(flags2)+p32(old_offset)+p16(cur_column)+p8(vtable_offset)+p8(shortbuf)+p32(lock)+p32(offset)+p32(codecvt)+p32(wide_data)+p32(freeres_list)+p32(freeres_buf)+p32(pad5)+p32(mode)+unused2+p32(0)*6+p64(vtable)
        elif self.arch==64:
            return p32(flags)+p32(0)+p64(read_ptr)+p64(read_end)+p64(read_base)+p64(write_base)+p64(write_ptr)+p64(write_end)+p64(buf_base)+p64(buf_end)+p64(save_base)+p64(backup_base)+p64(save_end)+p64(markers)+p64(chain)+p32(fileno)+p32(flags2)+p64(old_offset)+p16(cur_column)+p8(vtable_offset)+p8(shortbuf)+p32(0)+p64(lock)+p64(offset)+p64(codecvt)+p64(wide_data)+p64(freeres_list)+p64(freeres_buf)+p64(pad5)+p32(mode)+unused2+p64(vtable)

class IO_jump_t(object):
    def __init__(self,arch=64):
        '''
        struct _IO_jump_t{
            JUMP_FIELD(size_t, __dummy);
            JUMP_FIELD(size_t, __dummy2);
            JUMP_FIELD(_IO_finish_t, __finish);
            JUMP_FIELD(_IO_overflow_t, __overflow);
            JUMP_FIELD(_IO_underflow_t, __underflow);
            JUMP_FIELD(_IO_underflow_t, __uflow);
            JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
            JUMP_FIELD(_IO_xsputn_t, __xsputn);
            JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
            JUMP_FIELD(_IO_seekoff_t, __seekoff);
            JUMP_FIELD(_IO_seekpos_t, __seekpos);
            JUMP_FIELD(_IO_setbuf_t, __setbuf);
            JUMP_FIELD(_IO_sync_t, __sync);
            JUMP_FIELD(_IO_doallocate_t, __doallocate);
            JUMP_FIELD(_IO_read_t, __read);
            JUMP_FIELD(_IO_write_t, __write);
            JUMP_FIELD(_IO_seek_t, __seek);
            JUMP_FIELD(_IO_close_t, __close);
            JUMP_FIELD(_IO_stat_t, __stat);
            JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
            JUMP_FIELD(_IO_imbue_t, __imbue);
        };
        '''
        self.arch = arch
    def construct(self,dummy=0,dummy2=0,finish=0,overflow=0,underflow=0,uflow=0,pbackfail=0,xsputn=0,xsgetn=0,seekoff=0,seekpos=0,setbuf=0,sync=0,doallocate=0,read=0,write=0,seek=0,close=0,stat=0,showmanyc=0,imbue=0):
        if self.arch==32:
            return p32(dummy)+p32(dummy2)+p32(finish)+p32(overflow)+p32(underflow)+p32(uflow)+p32(pbackfail)+p32(xsputn)+p32(xsgetn)+p32(seekoff)+p32(seekpos)+p32(setbuf)+p32(sync)+p32(doallocate)+p32(read)+p32(write)+p32(seek)+p32(close)+p32(stat)+p32(showmanyc)+p32(imbue)
        elif self.arch==64:
            return p64(dummy)+p64(dummy2)+p64(finish)+p64(overflow)+p64(underflow)+p64(uflow)+p64(pbackfail)+p64(xsputn)+p64(xsgetn)+p64(seekoff)+p64(seekpos)+p64(setbuf)+p64(sync)+p64(doallocate)+p64(read)+p64(write)+p64(seek)+p64(close)+p64(stat)+p64(showmanyc)+p64(imbue)

def find_IO_str_jumps(fname):
    libc = ELF(fname)
    IO_file_jumps_offset = libc.sym[b'_IO_file_jumps']
    IO_str_underflow_offset = libc.sym[b'_IO_str_underflow']
    for ref_offset in libc.search(p64(IO_str_underflow_offset)):
        possible_IO_str_jumps_offset = ref_offset - 0x20
        if possible_IO_str_jumps_offset > IO_file_jumps_offset:
            return possible_IO_str_jumps_offset

###Reference
#  https://code.woboq.org/userspace/glibc/libio/bits/types/struct_FILE.h.html
#  https://code.woboq.org/userspace/glibc/libio/libioP.h.html
#  https://code.woboq.org/userspace/glibc/libio/libio.h.html
