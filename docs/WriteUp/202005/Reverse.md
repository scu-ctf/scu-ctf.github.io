# 2020 geekgame(scuctf) Reverse出题思路&writeup

## 真正的签到

### 出题思路

本身作为签到题就没必要太刁难人，主要考察脱压缩壳（re选手基础技能），正好在4月的脱壳分享会也说了要出一道这种题。脱完壳后就打算搞个简单的加减乘除，但是还是出题时候考虑不周，出现了多解的情况。（按照正常思路一般都是一个解。）

问题主要出在当时做了一个除法的操作，因为C语言中5/2 与4/2都为2。

### 解题方法

#### 法1

* 第一步，查壳，发现为upx。

  ![1](https://cdn.jsdelivr.net/gh/loveminhal/myblog-picgo/blog/20200526001329.png)

  

* 直接可以用脱壳软件脱壳也可esp定律等手动脱壳。

* 脱壳后分析代码。

  ![2](https://cdn.jsdelivr.net/gh/loveminhal/myblog-picgo/blog/20200526001330.png)

* 直接写脚本

  ```c
  #include<stdio.h>
  #include<string.h>
  int main(){
    	char fstr[17] = "pbm`KkL`dKQ2KeJLd";
    	char theflag[17];
  	char flag[17] = "scu_ctf_f4k3_f14g";	
  	int i = 0;       
      for(i = 0; i < 17; i++)
      theflag[i] = fstr[i]*2-flag[i]; 
      for(i = 0; i < 17; i++)
      printf("%c",theflag[i]);      
    }
  ```

### 法2

* 前面步骤一直，后面直接angr梭哈

```python
import angr
p = angr.Project('sign.exe', auto_load_libs=False)
st = p.factory.call_state(addr=0x401520, add_options=angr.options.unicorn)
sim = p.factory.simgr(st)
sim.explore(find=0x40155e, avoid=0x40156c)
print(sim.one_found.posix.dumps(0))
```

这个地方就可以看出，有多解情况了。

## 太空大战

### 出题思路

  这题是由God sun出的，大概主要考察一个.net，加之让比赛变的更有趣一点，放了个小游戏上去。只要打完180个灰机（一个不落）控制台就会输出flag

  （180个飞机，无需逆向，轻轻松松就可以打败。

### 解题方法

* 关键代码在assets/bin/Date/Managed/Assembly-CSharp.dll
* ⽤.NET Reflector打开分析

![3](https://cdn.jsdelivr.net/gh/loveminhal/myblog-picgo/blog/20200526001334.jpg)

* 经过分析可以得知，每击落一架分级，调用一次这个关键方法。由代码可以看到总共需要摧毁了180个。（其实总共也就180个）

* 写解题脚本

  ```python
  import hashlib
  mask =[49552,26516,15988,29987,52902,33151,8086,39920,3604,21497,19862,12268,50822,26111,35391,20661,6370,14029,26707,42890,19391,13836,61102,38705,45159,12927,47794,39183,20776,44532,18925,4854,60596,11941,28994,11166,57586,48918,13199,42006,62781,31480,50464,53893,21233,61456,55842,46591,10574,45253,50991,44866,45945,17105,27273,18925,41001,64310,51846,46279,14977,61079,26330,1192,61190,38989,36161,17001,38576,49567,55929,31759,54550,12759,13756,60929,36365,27308,57132,42483,42263,57086,55839,13568,37191,18388,34592,4189,65492,24673,27016,6941,33229,	4180,35454,64874,36708,22948]
  l = len(mask)
  secret = "jFEQ6xFkUxKGzUbn"
  
  for i in range(1,181):
      secret = hashlib.md5((secret+str(mask[i%l])).encode()).hexdigest()
      if '6a37460f25c719a4' in secret:
          print (secret[0:16])
  ```
  
* 注意这里很多选手以为只调用一次，所以直接拿180%98 去处理，算出来的是错的。

## PY 交易

### 出题思路 

这个题目出题主要想考察一下python的逆向，校内打校外比赛的不多，见得题目相对较少。所以本着拓宽学习的目的，出了这道还原字节码的题目。相对来说这道题不是太难，通过相关博客搜索，然后一步步分析还原，还原后dis检验。

* 参考文章 <https://bbs.pediy.com/thread-246683.htm>

### 解题方法

* 首先直接还原python代码就好了，还原结果如下

  ```python
  inputs = input("please your flag:")
  inputs = inputs[7:-1]
  flag = "th31_scuctf_eXclus1v3"
  theflag = ""
  i = 0
  j =0 
  print(flag[0])
  if(len(flag) != len(inputs)):
      print("Error!")
  for i in range(0,len(flag)-14):
      theflag += (chr(ord(flag[i])+ord(inputs[i+8])))
  for i in range(10,len(flag)-6):
      theflag += (chr(ord(flag[i])+ord(inputs[i-8])))
      j = i+1
  for i in range(j,len(flag)):
      theflag += (chr(ord(flag[i-3])+ord(inputs[i])))
  flags =list(theflag)
  for i in range(0,len(flags)//2):
      flags[i] = chr(ord(flags[i])+20)
  
  #Flag scuctf{}
  #The flag text starts with "d1" and the eighth bit is "3"
  flagt = flags[len(flags)//2:len(flags)]
  theflag = "".join(flagt)
  for k in range(0,len(flags)//2):
      theflag += "".join(flags[k])
  if(theflag == '×\x8bÙÍ\x8cÓÜî¤ú±¬¤¤úÖíÒ'):
      print("You win!")
  else:
      print("Error!!!")
  ```

* 接着就是逆向分析，写解题脚本

#### 法1

```python
enflag = '×\x8bÙÍ\x8cÓÜî¤ú±¬¤¤úÖíÒ'
flag = 'th31_scuctf_eXclus1v3'
ans = 'd1' + '_' * 19
step1 = enflag[9:] + enflag[0:9]
print(ans)
print(step1)
theflag = ''
for i in range(0,9):
theflag += chr(ord(step1[i]) - 20)
theflag += step1[9:]
print(theflag)
inputs = list(ans)
for i in range(0,7):
inputs[i + 8] = chr(ord(theflag[i]) - ord(flag[i]))
for i in range(10,15):
inputs[i - 8] = chr(ord(theflag[i - 3]) - ord(flag[i]))
for i in range(15,21):
inputs[i] = chr(ord(theflag[i - 3]) - ord(flag[i - 3]))
inputs[7] = '3'
print('scuctf{' + ''.join(inputs) + '}')
```

###  法2

```python
from z3 import *

flag = "th31_scuctf_eXclus1v3"
dist = "×ÙÍÓÜî¤ú±¬¤¤úÖíÒ"
inp = [BitVec(('x%s' % i), 8) for i in range(len(flag))]
theflag = []
for i in range(0, len(flag) - 14):
    theflag.append(ord(flag[i]) + inp[i + 8])
for i in range(10, len(flag) - 6):
    theflag.append(ord(flag[i]) + inp[i - 8])
for i in range(len(flag) - 6, len(flag)):
    theflag.append(ord(flag[i - 3]) + inp[i])
flags = [_ for _ in theflag]
for i in range(len(flags) // 2):
    flags[i] = flags[i] + 20

theflag = theflag[len(flags) // 2:]
for i in range(len(flags) // 2):
    theflag.append(flags[i])
solver = Solver()
for i in zip(theflag, dist):
    solver.append(i[0] == ord(i[1]))
solver.check()
model = solver.model()
for i, v in enumerate(inp):
    try:
        print(chr(model[v].as_long()), end='')
    except:
        print(' ', end='')
```

* 题目前两位和第八位无法解除，题目中已经提示具体字符

## ONIbase64

### 出题思路

本道题主要就是考察一个ollvm平坦化。也没想到这么惨烈。

### 解题方法

* 文件拉到最后就可以看到编译器地址，直接把它pull下来，编译.s文件得到可执行文件。

* 拖入IDA分析，是个标准的平坦化。

  ![6](https://cdn.jsdelivr.net/gh/loveminhal/myblog-picgo/blog/20200526001331.png)
  
* 参考<https://github.com/pcy190/deflat >去除平坦化

* 然后直接F5写解密脚本

  ```python
  from z3 import *
  from functools import reduce
  table = 'ZAnUX1W2oPNQ4sBMOd/+ChfGI5r8Hvt3uaLkbDgcyJYTipez6mxF0SEqRjVKwl97'
  coding = '5auRs6a4A2lEUObG5+uoPGuWHnimZLXtvkyEHxCFoal5'
  dist = map(lambda x: BitVecVal(table.find(x), 6), coding)
  flag = [BitVec('c%d' % i, 8) for i in range(32)]
  total = Concat(flag)
  s = [Extract(32 * (i + 1) - 1, 32 * i, total) for i in range(8)]
  temps = reduce(lambda x, y: x ^ y, s, 0)
  s = [i ^ temps for i in s]
  s.reverse()
  total = Concat(s)
  bits = [Extract(8 * (i + 1) - 1, 8 * i, total) for i in range(32)]
  bits = bits + [reduce(lambda x, y: x ^ y, bits)]
  tup = [bits[i:i + 3] for i in range(0, len(bits), 3)]
  outs = []
  padding = BitVecVal(0, 2)
  for i, v in enumerate(tup):
  t = Concat(v)
  s1 = Extract(23, 18, t)
  s2 = Extract(17, 12, t)
  s3 = Extract(11, 6, t)
  s4 = Extract(5, 0, t)
  outs.append(s1)
  outs.append(s2)
  outs.append(s3)
  outs.append(s4)
  for v2 in tup[i + 1:]:
  v2[0] = v2[0] ^ Concat(padding, s1)
  v2[1] = v2[1] ^ Concat(padding, s2)
  v2[2] = v2[2] ^ Concat(padding, s3)
  solve = Solver()
  for i, v in enumerate(dist):
  solve.add(outs[i] == v)
  solve.check()
  model = solve.model()
  print(''.join(map(lambda x: chr(model.eval(x, 8).as_long()),
  reversed(flag))))
  ```

  

## easy_re&easy_base

### 出题思路

既然要搞花样，当然少不当今最火的iot。采用腾讯TencentOS tiny 官方定制IoT开发板EVB_LX(暂时是限量的)编译环境： <https://github.com/Tencent/TencentOS-tiny>两个题目，都是考察找到被替换的base64密码表，由于考虑到直接上base有点难，所以出了一个easy_re过渡。

两个题目替换都涉及四段字符如下（把初始密码表拆分为四段）：

>	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
>	"abcdefghijklmnopqrstuvwxyz"
>	"0123456789"
>	"+/"

easy_re是改变了这四段字符压栈顺序。没想到ida太过于智能化，显示结果即是正确压栈顺序。

easy_base考察偏难了，主要是对这四段字符进行了一些变换，如果逆向分析的话需要学习risc-v指令集。

当然，这两个题最简单的方法是把程序放入对应开发板里，他相应的串口也会输出字母表。

做题过程中也发现一些选手拿到题目直接猜测arm架构，拿着ida 当arm分析，还原的内容是错的，无从下手。如果拿到文件后File一下也会知道是risc-v架构。不至于走偏。

### 解题方法

* 首先，ida默认不支持risc-v，所以需要下载相关插件。<https://github.com/lcq2/riscv-ida>

* 然后，ida打开分析，直接就有正确的字母表压栈顺序，（原本是想让选手分析简单指令来确定或者爆破）

  ![4](https://cdn.jsdelivr.net/gh/loveminhal/myblog-picgo/blog/20200526001332.png)

* 得到 字母表就很容易解出来了

```python
import base64
str1 = "PalXPrhnOrLZT6PVQJ1oNr9dSqDVTbo=="
string1 =
"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+/abcdefghijklmnopqrstuvwxyz"
string2 =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
print(base64.b64decode(str1.translate(str.maketrans(string1, string2))))
```

* easy_base 的话就需要分析指令得出具体操作或者直接开发板跑一下得到输出

* 看到大多数人解题无果，比赛最后放出了一个risc-v 64位的附件（代码一样），通过docker跑即可得到table。

  ![5](https://cdn.jsdelivr.net/gh/loveminhal/myblog-picgo/blog/20200526001333.jpg)

* 然后直接解密得到flag
``` python
import base64
str1 = "UoH+U/DJV/YlQdUOU94JPYxJgdHMUWK="
string1 =
"a0b1c2d3e4f5g6h7i8j9ZYXWVUTSRQPON+klmnopqrABCDEFGHIJKLM/stuvwxyz"
string2 =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
print(base64.b64decode(str1.translate(str.maketrans(string1, string2))))
```



* 如果对题目感兴趣的，可以之后再研究。我附上题目主文件源代码

``` C
#include "mcu_init.h"
#include "tos_k.h"

#define TASK_SIZE 1024
k_task_t k_task_task1;
k_task_t k_task_task2;
uint8_t k_task1_stk[TASK_SIZE];
uint8_t k_task2_stk[TASK_SIZE];

int share = 0xCBA7F9;
k_sem_t sem;
unsigned char *scuctf_flag_base64="UoH+U/DJV/YlQdUOU94JPYxJgdHMUWK=";
unsigned char base64_right[65]="";

void scuctf_base64(void)
{
	unsigned char base64_1[26]="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned char base64_2[26]="abcdefghijklmnopqrstuvwxyz";
	unsigned char base64_3[10]="0123456789";
	unsigned char base64_4[2]="+/";
	int i=0,j=0,k=0,q=25,r=10,n=0;
	for(i=0;i<20;)
	{
		base64_right[i]=base64_2[j];
		j++;
		base64_right[i+1]=base64_3[k];
		k++;
		i+=2;
	}
	for(i=20;i<33;i++)
	{
		base64_right[i]=base64_1[q];
		q--;
	}
	for(i=33;i<42;i++)
	{
		if(i==33)
		{
			base64_right[33]=base64_4[0];
		}
		else
		{
			base64_right[i]=base64_2[r];
			r++;
		}
	}
	for(i=42;i<64;i++)
	{
		if(n<13)
		{
			base64_right[i]=base64_1[n];
			n++;
		}
		else
		{
			if(i==55)
			{
				base64_right[i]=base64_4[1];
			}
			else
			{
				base64_right[i]=base64_2[r];
				r++;
			}
		}
	}
}

void task1(void *pdata)
{
    int task_cnt1 = 0;
    while (1) {
        printf("welcome scuctf from %s cnt: %d\n", __func__, task_cnt1++);
        tos_sem_pend(&sem, ~0U);
        gpio_bit_write(GPIOA, GPIO_PIN_7, share % 2);
    }

}

void task2(void *pdata)
{
    int task_cnt2 = 0;
    scuctf_base64();
    while (1) {
        share++;
        for(int i=0; i<5; i++) {
            printf("Where is scuctf_base64? %s cnt: %08x\n%s", __func__, task_cnt2--,base64_right);
            tos_task_delay(50);
        }
        tos_sem_post(&sem);
    }
}


void main(void) {
    board_init();

    usart0_init(115200);

    tos_knl_init();


    tos_task_create(&k_task_task1, "task1", task1, NULL, 3, k_task1_stk, TASK_SIZE, 0);
    tos_task_create(&k_task_task2, "task2", task2, NULL, 3, k_task2_stk, TASK_SIZE, 0);
    k_err_t err = tos_sem_create(&sem, 1);
    if (err != K_ERR_NONE) {
        goto die;
    }
    tos_knl_start();
die:
    while (1) {
        asm("wfi;");
    }
}
int _put_char(int ch)
{
    usart_data_transmit(USART0, (uint8_t) ch );
    while (usart_flag_get(USART0, USART_FLAG_TBE)== RESET){
    }
    return ch;
}
```

* 参考<https://github.com/riscv/riscv-isa-manual/releases>

## 小结

由于是普通校赛，题目也没出过分难，个人感觉难以把握还算可以。这次题目主要也本着打破传统scuctf 常规题目，一丢丢小小的创新。 .NET，risc-v，ollvm，apk，python等。即使这些可能在全国ctf中是常见题目，但是感觉校内还是几乎没出的。比赛过程中也发生了很多趣味东西，比如第一题一题多解，flag设置时候多加了空格导致选手提交报错等好多问题。

总之希望scuctf越来越有趣，参与人数越来越多吧！