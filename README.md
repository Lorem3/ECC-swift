

// todo
+ [ ] 改用使用通用大数库 libtommath.git
+ [x] 去掉libSecpk256.a 实现,自己实现曲线算法
--- 
2022-4-19  
使用 veclib 里面的 vU512 大数 实现椭圆曲线 secp256k1   

--- 
增加Salsa20 加密算法 并设置为默认
增加Scrypt算法,根据密码短语生成对应的密钥 取代的pbkdf2
```
N = 16384 r = 8 p = 1
salt [length 414]:
The California sea lion (Zalophus californianus) is a coastal species of eared seal native to western North America. It is one of six species of sea lion. Its natural habitat ranges from southeast Alaska to central Mexico, including the Gulf of California. This female sea lion was photographed next to a western gull in Scripps Park in the neighborhood of La Jolla in San Diego, California. [2022-04-07 wikipedia]
```

# 改用 swift改写

# LTEcc

# 利用椭圆曲线`secp256k1` 进行加解密工具
这条曲线用的比较少，macos 没有这个曲线的实现，
我用到了 比特币里面的 libsecp256k1.a 实现。
关于ecc 曲线加密，可以看看[这篇文章](https://vitock.github.io/2020/10/21/541a3f0129ff/)。

## 生成密钥对
> ecc g 


或者指定随机私钥 (32字节的base64 ) 
> ecc g -s  ZGLesiQ5A09PfRDDvJqNM7FxZcf2j0dMeGyV0E/A74Q=  
> // 保存到keychain   -S
> ecc g -s  ZGLesiQ5A09PfRDDvJqNM7FxZcf2j0dMeGyV0E/A74Q= -S 
> 


输出 会显示公钥和私钥,同时显示私钥的sha256指纹,以及其randomart
```

ECC encryption privateKey finggerprint: 
ZGLesiQ5A09PfRDDvJqNM7FxZcf2j0dMeGyV0E/A74Q=
randomart:

+---[Secp251k1]---+
|       o+. . o+++|
|       .ooo + oo*|
|  . . + ++.o . O.|
|   + *o=o.    E *|
|    * =XS      * |
|     =Bo.     . +|
|      .o       . |
|                 |
|                 |
+----[SHA 256]----+

0/1 = 123/133   0.519531


priKey:A5ey2d8ddoiSCxW2p/2RnLbME1YyrrCaVbyONF7ynuQ=
pubKey:BKZ2iYIYZxAtxsw/ovquy67sS5nhVoWydYB+JEvwMxMRM26tdCux0f7oSuUgMZa/Sqh3+7ZqWTONarra2BGW9OM=


```


## 加密

>  ecc e -p BGjWSuufcBmXmfM6Tdvu0GQfhQRmigD9hD+C+cDgdAKRGug/ZTPC4eZrMlGR3dv4A798g4SyvyoJAg+wWUgOIMo= -m hello 

或者
> cat a.txt | ecc -p BGjWSuufcBmXmfM6Tdvu0GQfhQRmigD9hD+C+cDgdAKRGug/ZTPC4eZrMlGR3dv4A798g4SyvyoJAg+wWUgOIMo= 

默认输出是二进制,如果想base64 输出可以,使用pip

 ecc e -p BGjWSuufcBmXmfM6Tdvu0GQfhQRmigD9hD+C+cDgdAKRGug/ZTPC4eZrMlGR3dv4A798g4SyvyoJAg+wWUgOIMo= -m hello | base64


加密文件
> ecc e -f SFBJ.txt  // -p 指定公钥,不指定就从keychain读取, -o 指定目标文件

解密 文件
> ecc d -f  SFBJ.txt.ec // -s 指定私钥,不指定就从keychain读取, -o 指定目标文件
 ## 解密
 

 > echo 'encrypte base64 ' | base64 -d | ecc d -s A5ey2d8ddoiSCxW2p/2RnLbME1YyrrCaVbyONF7ynuQ=

 ## randomart 
 这是我在ssh-keygen 上第一次看到,觉得蛮有趣的,就自己弄了
 个。decode方法出来结果不是很好，因为太容易冲突了。
 > ecc r -m message
 

 ```
 ecc r -m 'hello world'
+-----------------+
|                 |
|       o         |
|      . E . o    |
|       O = *     |
|      o S = *    |
|     .   . =     |
|                 |
|                 |
|                 |
+-----------------+


 ```

