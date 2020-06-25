# ropes  
> It's not just a string, it's a rope!  

You can solve this by using command `strings ./ropes`  
flag : `flag{r0pes_ar3_just_l0ng_str1ngs}`  

# bubbly  
> It never ends  
> nc 2020.redpwnc.tf 31039  
After looking at a dissasembler, this program basically make a manual bubble sort, our input `i` is an integer that will be used as index to swap 2 integer on the `nums` array.  
Instead of searching for bubble sort code online and modify it so we can see the index swapped, I ended up doing the whole thing by hand, here's what I came up:  
```
$ nc 2020.redpwnc.tf 31039
I hate my data structures class! Why can't I just sort by hand?
2
1
2
3
4
5
6
7
8
4
5
6
7
4
5
6
4
5
3
9
Well done!
```
flag : `flag{4ft3r_y0u_put_u54c0_0n_y0ur_c011ege_4pp5_y0u_5t1ll_h4ve_t0_d0_th15_57uff}`