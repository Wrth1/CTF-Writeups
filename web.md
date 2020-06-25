# pastebin  
> I wanted to make a website to store bits of text, but I don't have any experience with web development. However, I realized that I don't need any! If you experience any issues, make a paste and send it [here](https://admin-bot.redpwnc.tf/submit?challenge=static-pastebin)  
> Site: https://static-pastebin.2020.redpwnc.tf  
For this challenge I use a very nice [tool](https://xsshunter.com/) to solve it, the flag is the admin's cookie  
flag : `flag{54n1t1z4t10n_k1nd4_h4rd}`  

# panda-facts  
> I just found a hate group targeting my favorite animal. Can you try and find their secrets? We gotta take them down!  
> Site: panda-facts.2020.redpwnc.tf  
The concept is pretty much the same with any injection vulnerabilities, we can insert `name", "member" : 1, "x" : "somethingtomatchthequotationmarks` as our username, and it will inject a value of member and set it to 1, then x just to match the quotation marks.

flag : `flag{1_c4nt_f1nd_4_g00d_p4nd4_pun}`