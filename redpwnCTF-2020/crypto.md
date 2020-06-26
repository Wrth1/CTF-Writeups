# base646464
> Encoding something multiple times makes it exponentially more secure!  

just decode the ciphertext 25 times.  
```python
from base64 import b64decode
with open("cipher.txt",'r') as f:
        c = f.read()
        for i in range(25):
                c = b64decode(c)
        print (c.decode())
```
flag : `flag{l00ks_l1ke_a_l0t_of_64s}`  

# pseudo-key  
> Keys are not always as they seem...  
> Note: Make sure to wrap the plaintext with flag{} before you submit!  

The first thing we need to do is to find the key, however each key map to 2 possibilites, for example, if the encrypted key is `a` then the possibilities will be either `a` or `n` because `0 + 0 % 26 = 0` and `13 + 13 %26 = 0`. So we have to find those 2 possibilities, and then try all possible combinations from those 2 possibilities.  
I just bruteforce everything with my ugly script    
```python
from string import ascii_lowercase

chr_to_num = {c: i for i, c in enumerate(ascii_lowercase)}
num_to_chr = {i: c for i, c in enumerate(ascii_lowercase)}

cipher = "z_jjaoo_rljlhr_gauf_twv_shaqzb_ljtyut"
enc_key = "iigesssaemk"
key = ""
flag = ""
# candidates = []
# for i in enc_key:
# 	for j in ascii_lowercase:
# 		if num_to_chr[(chr_to_num[j]*2)%26] == i:
# 			candidates.append(j)
# 			# key += j
# 	print (candidates)
# 	candidates = []

for i in['e', 'r']:
	for j in['e', 'r']:
		for k in['d', 'q']:
			for l in['c', 'p']:
				for m in['j', 'w']:
					for n in['j', 'w']:
						for o in['j', 'w']:
							for p in['a', 'n']:
								for q in['c', 'p']:
									for r in['g', 't']:
										for s in['f', 's']:
											key = i+j+k+l+m+n+o+p+q+r+s
											key = key*((len(cipher)//len(key))+1)
											for c in range(len(cipher)):
												if cipher[c] == '_':
													flag += '_'
													continue
												for randkey in ascii_lowercase:
													if num_to_chr[(chr_to_num[randkey]+chr_to_num[key[c]])%26] == cipher[c]:
														flag += randkey
														break
											print('flag{'+flag+'}')
											flag = ""
```
But it works!  
flag = `flag{i_guess_pseudo_keys_are_pseudo_secure}`  

# 4k-rsa  
> Only n00bz use 2048-bit RSA. True gamers use keys that are at least 4k bits long, no matter how many primes it takes.  

using [factordb](factordb.com) we can see that there are many prime factors of n, the way we can decrypt the ciphertext is pretty much the same with normal RSA, just multiply each factor-1 to calculate phi.  
```python
from Crypto.Util.number import long_to_bytes as ltb
n = 5028492424316659784848610571868499830635784588253436599431884204425304126574506051458282629520844349077718907065343861952658055912723193332988900049704385076586516440137002407618568563003151764276775720948938528351773075093802636408325577864234115127871390168096496816499360494036227508350983216047669122408034583867561383118909895952974973292619495653073541886055538702432092425858482003930575665792421982301721054750712657799039327522613062264704797422340254020326514065801221180376851065029216809710795296030568379075073865984532498070572310229403940699763425130520414160563102491810814915288755251220179858773367510455580835421154668619370583787024315600566549750956030977653030065606416521363336014610142446739352985652335981500656145027999377047563266566792989553932335258615049158885853966867137798471757467768769820421797075336546511982769835420524203920252434351263053140580327108189404503020910499228438500946012560331269890809392427093030932508389051070445428793625564099729529982492671019322403728879286539821165627370580739998221464217677185178817064155665872550466352067822943073454133105879256544996546945106521271564937390984619840428052621074566596529317714264401833493628083147272364024196348602285804117877
e= 65537
c= 3832859959626457027225709485375429656323178255126603075378663780948519393653566439532625900633433079271626752658882846798954519528892785678004898021308530304423348642816494504358742617536632005629162742485616912893249757928177819654147103963601401967984760746606313579479677305115496544265504651189209247851288266375913337224758155404252271964193376588771249685826128994580590505359435624950249807274946356672459398383788496965366601700031989073183091240557732312196619073008044278694422846488276936308964833729880247375177623028647353720525241938501891398515151145843765402243620785039625653437188509517271172952425644502621053148500664229099057389473617140142440892790010206026311228529465208203622927292280981837484316872937109663262395217006401614037278579063175500228717845448302693565927904414274956989419660185597039288048513697701561336476305496225188756278588808894723873597304279725821713301598203214138796642705887647813388102769640891356064278925539661743499697835930523006188666242622981619269625586780392541257657243483709067962183896469871277059132186393541650668579736405549322908665664807483683884964791989381083279779609467287234180135259393984011170607244611693425554675508988981095977187966503676074747171
primes = [9353689450544968301, 9431486459129385713, 9563871376496945939, 9734621099746950389, 9736426554597289187, 10035211751896066517, 10040518276351167659, 10181432127731860643, 10207091564737615283, 10435329529687076341, 10498390163702844413, 10795203922067072869, 11172074163972443279, 11177660664692929397, 11485099149552071347, 11616532426455948319, 11964233629849590781, 11992188644420662609, 12084363952563914161, 12264277362666379411, 12284357139600907033, 12726850839407946047, 13115347801685269351, 13330028326583914849, 13447718068162387333, 13554661643603143669, 13558122110214876367, 13579057804448354623, 13716062103239551021, 13789440402687036193, 13856162412093479449, 13857614679626144761, 14296909550165083981, 14302754311314161101, 14636284106789671351, 14764546515788021591, 14893589315557698913, 15067220807972526163, 15241351646164982941, 15407706505172751449, 15524931816063806341, 15525253577632484267, 15549005882626828981, 15687871802768704433, 15720375559558820789, 15734713257994215871, 15742065469952258753, 15861836139507191959, 16136191597900016651, 16154675571631982029, 16175693991682950929, 16418126406213832189, 16568399117655835211, 16618761350345493811, 16663643217910267123, 16750888032920189263, 16796967566363355967, 16842398522466619901, 17472599467110501143, 17616950931512191043, 17825248785173311981, 18268960885156297373, 18311624754015021467, 18415126952549973977]
phi = 1
for i in primes:
	phi *= i-1

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
d = modinv(e,phi)
print (ltb(pow(c,d,n)).decode())
```
flag : `flag{t0000_m4nyyyy_pr1m355555}`

# primimity  
> People claim that RSA with two 1024-bit primes is secure. But I trust no one. That's why I use three 1024-bit primes.  
> I even created my own prime generator to be extra cautious!  

if we look at the source code, we can see that each prime is only differ by a few primes away, the way we can factor it is by taking the cube root of n, then keep calling nextprime() until it become one of the factor of n. you can see the code that I wrote to bruteforce that in the commented code below :  
```python
from sympy import nextprime
from gmpy2 import root
from Crypto.Util.number import long_to_bytes as ltb
n= 2739699434633097765008468371124644741923408864896396205946954196101304653772173210372608955799251139999322976228678445908704975780068946332615022064030241384638601426716056067126300711933438732265846838735860353259574129074615298010047322960704972157930663061480726566962254887144927753449042590678730779046154516549667611603792754880414526688217305247008627664864637891883902537649625488225238118503996674292057904635593729208703096877231276911845233833770015093213639131244386867600956112884383105437861665666273910566732634878464610789895607273567372933766243229798663389032807187003756226177111720510187664096691560511459141773632683383938152396711991246874813205614169161561906148974478519987935950318569760474249427787310865749167740917232799538099494710964837536211535351200520324575676987080484141561336505103872809932354748531675934527453231255132361489570816639925234935907741385330442961877410196615649696508210921
q = 139926822890670655977195962770726941986198973494425759476822219188316377933161673759394901805855617939978281385708941597117531007973713846772205166659227214187622925135931456526921198848312215276630974951050306344412865900075089120689559331322162952820292429725303619113876104177529039691490258588465409494847
r = 139926822890670655977195962770726941986198973494425759476822219188316377933161673759394901805855617939978281385708941597117531007973713846772205166659227214187622925135931456526921198848312215276630974951050306344412865900075089120689559331322162952820292429725303619113876104177529039691490258588465409397803
p = (n/q)/r
assert p*q*r == n
e = 65537
c = 2082926013138674164997791605512226759362824531322433048281306983526001801581956788909408046338065370689701410862433705395338736589120086871506362760060657440410056869674907314204346790554619655855805666327905912762300412323371126871463045993946331927129882715778396764969311565407104426500284824495461252591576672989633930916837016411523983491364869137945678029616541477271287052575817523864089061675401543733151180624855361245733039022140321494471318934716652758163593956711915212195328671373739342124211743835858897895276513396783328942978903764790088495033176253777832808572717335076829539988337505582696026111326821783912902713222712310343791755341823415393931813610365987465739339849380173805882522026704474308541271732478035913770922189429089852921985416202844838873352090355685075965831663443962706473737852392107876993485163981653038588544562512597409585410384189546449890975409183661424334789750460016306977673969147
# p = root(n,3)
# tries = 0
# while n%p != 0:
# 	tries += 1
# 	print tries
# 	p = nextprime(p)
# print "------------------------------------------------------------------------------------------------------------"
# print p

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
phi = (p-1)*(q-1)*(r-1)
d = modinv(e,phi)
print ltb(pow(c,d,n))
```  
flag : `flag{pr1m3_pr0x1m1ty_c4n_b3_v3ry_d4ng3r0u5}`  

# itsy-bitsy
> The itsy-bitsy spider climbed up the water spout...  
> nc 2020.redpwnc.tf 31284  

If you look at the source code, any number between lower bound and upperbound have the same first bit, which is 1, so for example if `i = 1` and `j = 2`, then the range are `0b10` to `0b11`, so no matter what for first bit and each two index after, the flag bit will be xored by 1, and so for every prime number we can leak every single byte, and the only bit that can't be leaked is the flag_bit[1]. but it's just 2 possibilities, so we can just try both. You can see the script I used to leak all the bytes in the commented code below :
```python
from sympy import nextprime
import pwn
#len(flag_bits) == 301
# prime = nextprime(0)
# arr = ['?' for _ in range(301)]
# while prime < 301:
# 	try:
# 		print (prime)
# 		r = pwn.remote("2020.redpwnc.tf",31284)
# 		r.sendlineafter("i > 0: ",str(prime-1))
# 		r.sendlineafter("i > 0: ",str(prime))
# 		c = r.recv()[len("Ciphertext: "):]
# 		for i in range(0,len(arr),prime):
# 			arr[i] = str(int(c[i])^1)
# 		print (''.join(arr))
# 		prime = nextprime(prime)
# 		r.close()
# 	except:
# 		continue
# final output : '1?00110110110011000011100111111101111000101101001111010011100111011111110110011001011100001110101111010011101110110011110111111101111111010111101001011111110010011011111110111110111010111111110100110100011001011011111111011111000011110100110010111100101011111111001111100001101111111010111101001111101'
arr1 = '1000110110110011000011100111111101111000101101001111010011100111011111110110011001011100001110101111010011101110110011110111111101111111010111101001011111110010011011111110111110111010111111110100110100011001011011111111011111000011110100110010111100101011111111001111100001101111111010111101001111101'
arr2 = '1100110110110011000011100111111101111000101101001111010011100111011111110110011001011100001110101111010011101110110011110111111101111111010111101001011111110010011011111110111110111010111111110100110100011001011011111111011111000011110100110010111100101011111111001111100001101111111010111101001111101'
flag = ""
arr1 = [arr1[i:i+7] for i in range(0,len(arr1),7)]
arr2 = [arr2[i:i+7] for i in range(0,len(arr2),7)]
for i in arr1:
	flag += chr(int(i,2))
print (flag)
flag = ""
for i in arr2:
	flag += chr(int(i,2))
print (flag)
```  
flag : `flag{bits_leaking_out_down_the_water_spout}`

# alien-transmissions-v2  
> The aliens are at it again! We've discovered that their communications are in base 512 and have transcribed them in base 10. However, it seems like they used XOR encryption twice with two different keys! We do have some information:  
>   
> This alien language consists of words delimitated by the character represented as 481  
> The two keys appear to be of length 21 and 19  
> The value of each character in these keys does not exceed 255  
> Find these two keys for me; concatenate their ASCII encodings and wrap it in the flag format.  

This challenge is very fun, at its finest it is just combination of pseudo-key and itsy-bitsy, basically, every 399th character will be xored by the same key (21\*19), the first information basically says the space character is 481, and space character is the most common character in a text. So, we for example, if we want to find `481^key1[0]^key2[0]`, we can check every 399th characters, and look at the most common number , that number xored by 481 is `key1^key2`:
```python
import collections
f = open('encrypted.txt').read().split('\n')

i=0
j=0
tries=0
for pos1 in range(0,21):
	print ("----------" + str(pos1) + "------------")
	for pos2 in range(0,19):
		i = 0
		j = 0
		tries=0
		while True:
			if i==pos1 and j==pos2:
				# print pos2
				x = f[tries::399]
				print(collections.Counter(x).most_common(1)[0])
				# print tries
				break
			i += 1
			i=i%21
			j += 1
			j=j%19
			tries+=1
```
the output will look something like this : 
```
----------0------------
('470', 250)
('509', 301)
('481', 272)
('442', 279)
('470', 241)
('444', 274)
('442', 234)
('490', 254)
('441', 245)
('487', 265)
('493', 252)
('470', 264)
('440', 244)
('444', 233)
('470', 267)
('509', 279)
('481', 240)
('440', 253)
('444', 271)
----------1------------
('397', 252)
('422', 246)
('442', 220)
('481', 232)
('397', 262)
('487', 260)
('481', 257)
('433', 264)
('482', 257)
('444', 264)
('438', 240)
('397', 260)
('483', 263)
('487', 271)
('397', 264)
('422', 273)
('442', 242)
('483', 248)
('487', 245)
```
as you can see `481^key1[0]^key2[0]` has the same value as `481^key1[0]^key2[4]`, you can also see `481^key1[1]^key2[0]` is the same as `481^key1[1]^key2[4]`, that means our plan is working fine.  
the next thing we gonna do is to bruteforce to get the key, for example the first 19 lines contains `key1[0]^key2[0` to `key1[0]^key2[18]`, so if we can guess `key1[0]` correctly, we can recover the whole key2.  
```python
from string import printable
printable = printable[:-5]
key2_enc = [470,509,481,442,470,444,442,490,441,487,493,470,440,444,470,509,481,440,444]
key2 = ""
for i in printable:
	key2 = ''
	for j in key2_enc:
		key2 += chr(481^j^ord(i))
	print (key2)
```  
We can see that there is one line that is an english leet text. which is `_th3_53c0nd_15_th15`, this is it, this must be a key2. next step is we basically do the same thing but this time to recover key1 and we don't need to bruteforce anymore, we just use the first character of key2 which is `_`.  
```python
key1_enc = [470,397,460,397,409,395,481,458,470,397,481,472,399,460,395,458,481,470,394,466,472]
key2 = "_th3_53c0nd_15_th15"
key1 = ''
for i,j in zip(key1_enc,"_"*21):
	key1 += chr(481^i^ord(j))
print ("flag{" + key1 + key2 + '}')
```
flag : `flag{h3r3'5_th3_f1r5t_h4lf_th3_53c0nd_15_th15}`  
  
# worst-pw-manager  
> I found this in-progress password manager on a dead company's website. Seems neat.  
When we look at the masked_file_name, what the code does is actually rotate each character from password by its position. So we can recover the password already by rotating it back, however this will not help us get the flag yet.  
  
The next step is to take a look at the generate_key() function, the flag is cycled, so it was basically an endless string with the flag over and over again, the generate_key() function take every 8th character and make that the whole key. so if the 8th character from the flag is "a", that means the key will be [61,61,61,61,61,61,61,61] which is a hex representation of 'a'.  
We don't even need to analyze the rc4() function, because we have the password and it's ciphertext, we can just bruteforce the key.  
```python
from string import printable,ascii_lowercase

class KeyByteHolder(): # im paid by LoC, excuse the enterprise level code
    def __init__(self, num):
        assert num >= 0 and num < 256
        self.num = num
    def __repr__(self):
        return hex(self.num)[2:]

def rc4(text, key): # definitely not stolen from stackoverflow
    S = [i for i in range(256)]
    j = 0
    out = bytearray()
    #KSA Phase
    for i in range(256):
        j = (j + S[i] + key[i % len(key)].num) % 256
        S[i] , S[j] = S[j] , S[i]
    #PRGA Phase
    i = j = 0
    for char in text:
        i = ( i + 1 ) % 256
        j = ( j + S[i] ) % 256
        S[i] , S[j] = S[j] , S[i]
        out.append(ord(char) ^ S[(S[i] + S[j]) % 256])
    return out

    return [next(iterator) for _ in range(count)]

def generate_key(flag):
    key = [KeyByteHolder(0)] * 8 # TODO: increase key length for more security?
    for i, c in enumerate(flag): # use top secret master password to encrypt all passwords
        key[i].num = c
    return key

password_masked = {"0" : "135791","151" : "tfsxmjxv","203" : "mbtle","256" : "aoihpt","309" : "jbpxewe","361" : "abnlcfn",
"100" : "amgaesjyi","152" : "7890123","204" : "gbdumjrh","257" : "kfpqiyn","30" : "fskhriy","362" : "ppqnmj",
"101" : "amgamx","153" : "cighwj","205" : "imqyidub0","258" : "mbuwiw","310" : "fvenskl","363" : "jpjqgjth",
"102" : "jfuxw","154" : "161098","206" : "bbkoid","259" : "sdqrfd","311" : "amkfmf","364" : "lpxhptbl",
"103" : "etvuiqrh","155" : "asuhrfr","207" : "jfthqd","25" : "svpvlntl","312" : "njeksqgz","365" : "fveniw",
"104" : "mjixiq","156" : "dpnslnt","208" : "pbohpf","260" : "cbtpis","313" : "fmqziwy","366" : "acegik",
"105" : "wjnomfs","157" : "aovrrnu","209" : "kjoeiwrf","261" : "468024","314" : "cskvxngu","367" : "bfpmerou",
"106" : "tiqpex","158" : "hfcwljx","210" : "gfolrn","262" : "sfddwyohv","315" : "tjpwms","368" : "143658",
"107" : "bfcxxnlbt","159" : "dbxlh","211" : "sicqrtt","263" : "rfdhghg","316" : "bjcqgf","369" : "gbpjwyg",
"108" : "mznrzj","15" : "jfuvmhg","212" : "pjewywkz","264" : "jbenmj","317" : "citlwgxvew","36" : "jvuwms",
"109" : "aoihpf","160" : "gjpjiw","2" : "135791357","265" : "sqkgiwshv","318" : "cigvxjx","370" : "bsqroj",
"10" : "njerpj","161" : "sugslftpm","213" : "atuksqk","266" : "citlwyuwpnb","319" : "113355","371" : "345678",
"110" : "ppqkfjgy","162" : "pfcqyy","214" : "sprkmj","267" : "kbtlrf","31" : "bvvwiwlsg","372" : "hjrksu",
"111" : "pbvumhq","163" : "bmkqo649","215" : "jfuvmj","268" : "jpjqrd","320" : "snqnid","373" : "abcdef",
"112" : "imqyirk","164" : "sxghxnk","216" : "hfnospoabh","269" : "hpvpenr","321" : "sjnyiw","374" : "mzddfd",
"1" : "13579","165" : "234567","217" : "cmcxhng","26" : "ciqfsqgam","322" : "iovhvska","375" : "sftjmt",
"113" : "sbmxvf","16" : "666666","218" : "bbdbknxs9","270" : "0246802468","323" : "sxghx","376" : "wfnfsrk",
"114" : "aetles","166" : "bfcxxd","219" : "aoihpnih","271" : "sdjrsq","324" : "sutdagkyzh","377" : "mfvdpqoji",
"115" : "amgaesjlz","167" : "999999","21" : "imqyiz","272" : "bbtfiquui","325" : "gbtimjrk","378" : "jvnles",
"116" : "dfuwmse","168" : "vjewswoh","22" : "012345","273" : "avixwy","326" : "dfpqmx","379" : "tscymx",
"117" : "citlwyohv","169" : "hpphc","220" : "avuwms","274" : "osndriu","327" : "pbpjiy","37" : "lpxhqj",
"118" : "133557","170" : "01234","221" : "mbjdppu","275" : "sboxiq","328" : "fscqgny","380" : "mzusehk8",
"119" : "sbadrl","171" : "fftqesjv","222" : "vjewsw","276" : "cbohvtt","329" : "cbuvmj","381" : "bbdbfqal",
"11" : "dbpliq","172" : "ppmhqtt","223" : "hptvix","277" : "smksosua","32" : "pvtspj","382" : "sbdumsg",
"120" : "angumhg","173" : "mbijmj","224" : "tjhiese","278" : "cvvliuol","330" : "bfpimhg","383" : "mjekejr8",
"121" : "dbpfiw","174" : "cptddtt","225" : "mbtlesg","279" : "mppnid7","331" : "lpxh579","384" : "jfhivje",
"122" : "mpplgf","175" : "cikfojt","226" : "eewdviu","27" : "pbuvatxk9","332" : "608204","385" : "sugsljt",
"123" : "rjekewj","176" : "pfrsiw","227" : "aofuix","280" : "51ehry","333" : "atfikm","386" : "lpxh",
"124" : "124578","177" : "cskvxnth","228" : "cpwuxskf","281" : "bpplxf","334" : "lpnomuuw","387" : "dbmrxf",
"125" : "pskqgjyz9","178" : "rbkqftc","229" : "bpqest","282" : "kfxlr","335" : "omkymf","388" : "cbvkiwoum",
"126" : "567890","179" : "kjuvix","230" : "kjuvqj","283" : "bjvfl","336" : "cbpfiw","389" : "bbfesd",
"127" : "djcpssj","17" : "mjekejr","231" : "hbtoid","284" : "mbidrig","337" : "cbolpf","38" : "fvencta",
"128" : "cbtrpnth","180" : "mbpxiq","232" : "rppdpiu","285" : "bbdbfte","338" : "qxguxdapwy","390" : "fftqesjh",
"129" : "sugyis","181" : "mzusehk","233" : "imqyidub9","286" : "cbusiw","339" : "svrhvxzhz","39" : "135468",
"12" : "bbdbknxs","182" : "rfdhpik","234" : "psgfmtaz","287" : "bsgqhf","33" : "aoihp","391" : "wfuwpnll",
"130" : "rbpjiwy","183" : "aoihp6","235" : "odvrfjx","288" : "aekgex","340" : "hbtucuuabnb","392" : "bmqqhnk",
"131" : "lpwlwj","184" : "rjedviu","236" : "iowbexnh","289" : "kjvwis","341" : "iicwidub","393" : "sbuxoj",
"132" : "oscqkj","185" : "bbdbkzxs","237" : "pfcfljy","28" : "spefiw","342" : "cicupjy","394" : "snkoid",
"133" : "791791","186" : "hfcyis","238" : "vftrrnih","290" : "kbthr","343" : "mppluzk","395" : "jbenwtt",
"134" : "901234","187" : "56789","239" : "citlw","291" : "mvuwesm","344" : "mjfqmlna","396" : "sjospj",
"135" : "siquxd","188" : "bbuhffrs","23" : "mjekiqrl","292" : "itceiq","345" : "vjpfisz","397" : "mfndrnk",
"136" : "12345","189" : "mbtwms","240" : "890123","293" : "nbvdpnk","346" : "citlwyoum","398" : "sugdyf",
"137" : "nbvkes","18" : "atjoid","241" : "aetlesg","294" : "cvvhepu","347" : "aqroix","399" : "dpnslntz",
"138" : "soqrtd","190" : "gsghrigf","242" : "cvvli","295" : "jbxliw","348" : "sdqutnu","3" : "pbuvatxk",
"139" : "gbdumjr","191" : "npxhqgky","243" : "jbohw","296" : "791791791","349" : "jptges80","400" : "rpdhvyu",
"13" : "mppnid","192" : "amavwf","244" : "bbpdrf","297" : "135999","34" : "jptges","401" : "fmwijd",
"140" : "hvpwiw","193" : "mbflwtt","245" : "pskqgj","298" : "sbtdl","350" : "lpthrf","402" : "tfthwf",
"141" : "ciguvd","194" : "mpvkiw","246" : "fskhri","299" : "bpyzsb","351" : "aofuijg","403" : "pjioiy",
"142" : "kjnoiw","195" : "135666","247" : "jfuxw6","29" : "aovksse","352" : "mftfiikz","404" : "rppdpi",
"143" : "sbpgvf","196" : "135dfh","248" : "csavxfr","300" : "pptwylgs","353" : "kbvkiwoum","405" : "smkgixnve",
"144" : "amgmesjyw","197" : "mbjdppoai","249" : "cfnwmh","301" : "lbwue","354" : "cicuqjj","406" : "atfikmprt",
"145" : "bvuwiw","198" : "bbvpes","24" : "tjijiw","302" : "789012","355" : "ackjenr","407" : "mjpqmj",
"146" : "gfqukj","199" : "sfrwirhlz","250" : "zyeyfss","303" : "mbtyms","356" : "rbhdiq","408" : "nfybswq",
"147" : "bskwxftf","19" : "qxguxd","251" : "eeydvi","304" : "dfplwj","357" : "idgfvjgt",
"148" : "amgmesjyi","200" : "dfehqgky","252" : "omkyiw","305" : "tjihvx","358" : "mfzlgt",
"149" : "pbvumhoh","20" : "123456","253" : "djcqe","306" : "vpnoidhhtu","359" : "bskdrsg",
"14" : "lpxhpd","201" : "mptjes","254" : "sbovysm","307" : "jbusiw","35" : "ljxhvuuvt",
"150" : "rbekiq","202" : "mbtlttyh","255" : "fsghhts","308" : "rpenwygy","360" : "njtyesg"}
password = []
password_enc = []
for l in range(0,409):
	try:
		x = password_masked[str(l)]
		password_enc.append(open((str(l) + '_' + x + ".enc"),'rb').read())
	except:
		password.append("")
		password_enc.append("")
		continue	
	password.append("".join([chr((((c - ord("0") - i) % 10) + ord("0")) * int(chr(c) not in ascii_lowercase) + (((c - ord("a") - i) % 26) + ord("a")) * int(chr(c) in ascii_lowercase)) for c, i in zip([ord(a) for a in x], range(0xff))]))

flag = []
for i in range(0,len(password)):
	if password_enc[i] == '':
		continue
	for l in printable:
		testkey = [ord(l) for _ in range(8)]
		if rc4(password[i],generate_key(testkey)) == password_enc[i]:
			flag.append(l)
			break
print (''.join(flag))
```  
output :  
`ysnnltu_idr_aoug_iy_fptd_ics_htaopidr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug`  
the next thing to do is to find the key length, we can assume the key length as `len("ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}")`.  
```python
flag = ["X" for _ in range(len("ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}"))]
flag_enc = "ysnnltu_idr_aoug_iy_fptd_ics_htaopidr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug_iy_fptd_ics_htaopps}ysnnp{idtsltu_idr_aoug"
for i in range(len(flag_enc)):
	flag[(i*8)%len(flag)] = flag_enc[i]
print (''.join(flag))
```  
output : `id_and_python_is_stupid}flag{crypto_is_stup`  
My solution may look atupid and lazy but actually I tried to find some way to decrypt the rc4() function however I can't really find it, so I believe that this is the actual intended solution.  
  
flag : `flag{crypto_is_stupid_and_python_is_stupid}`
