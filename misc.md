# uglybash
> This bash script evaluates to echo dont just run it, dummy # flag{...} where the flag is in the comments.  
> The comment won't be visible if you just execute the script. How can you mess with bash to get the value right before it executes?  
> Enjoy the intro misc chal.  

My way on solving this challenge is by changing the `eval` command (was `e$'\u0076'al`) into `printf '%s\n`, then run it, and from the output, change the `/bin/bash` command (was `$BASH ${*%%Y#0C}   ${*,,} <<<`) into `printf '%s\n'` and run it.  
flag : `flag{us3_zsh,_dummy}`
