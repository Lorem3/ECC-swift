//
//  main.swift
//  ECC-swift
//
//  Created by wei li on 2022/3/7.
//

import Foundation


func readDataFromStdIn() -> Data{
    var c = 0 as  Int32
    // 30M
    let bfsize = (1 << 20) * 30
    let buffer = malloc( bfsize ).bindMemory(to: UInt8.self, capacity: bfsize)
    defer{
        free(buffer)
    }
    var t = 0;
    c = fgetc(stdin);
    repeat{
        buffer[t] = UInt8(c);
        t += 1;
        
        c = fgetc(stdin);
    }while c != EOF && t < bfsize
    
    let r = Data(bytes: buffer, count: t);
    return r;
    
}

func printKey(key:Data){
    let dataHash = try? LTBase64.base64Decode(key.sha256(base64: 1));
    let randomart = RandomArt.randomArt(data: dataHash! , title: "[Secp251k1]", end: "[SHA 256]");
    
    print("ECC encryption privateKey finggerprint:\n\(key.sha256(base64: 1))\nrandomart:\n\(randomart)");
    
    var ZeroCount = 0;
    var OneCount = 0;
    for var p in key{
        var c = 0
        while(p != 0) {
            p &= (p-1)
            c += 1;
        }
        OneCount += c;
        ZeroCount += 8-c;
    }
    print("0/1 = \(ZeroCount)/\(OneCount) = \(Float(ZeroCount)/Float(OneCount))");
    
    
    //    bit map
    //    for i in 0..<key.count{
    //        if(i % 3 == 0){
    //            print("");
    //        }
    //        let p = key[i];
    //        for j in 0..<8{
    //            if((p & (1 << j)) != 0){
    //                print("o" ,separator: "",terminator: "");
    //            }else{
    //                print("." ,separator: "",terminator: "");
    //            }
    //        }
    //    }
    //    print("\n")
    
}

let Version = "1.0.0"

let helpMsg = """
ecc \(Version)
g [-prikey/secKey/s prikey]  generate keypair [-k  passphrase/count pbkdf2] [-kt 1: scrypt default 2:pbkdf] [-S] saveto key chain
e  -pubkey/p pubkey -m msg [-f inputfilepath] [-o outpath]
   -a a:aes256 s:salsa20 default
d  -prikey/s prikey -m base64ciphermsg  binary data from stdin [-f inputfilepath] [-o outpath]
r  -m msg print random art of msg
s  show saved key in keychain

-z 0 ,if don't want gzip File(-f) before encrypt, sepecify this

if you dont want specify -s -p everytime ,
set EC_SECKEY or EC_PUBKEY on current ENV
export set EC_SECKEY=...
export set EC_PUBKEY=...
unset EC_PUBKEY EC_SECKEY
"""

do{
repeat{
    if CommandLine.arguments.count <= 1{
        print(helpMsg)
        break;
    }
    
    
    var strPreKey:String?
    var dicArg = Dictionary<String,Any>();
    for i in 1..<CommandLine.arguments.count{
        let argument = CommandLine.arguments[i];
        if argument.hasPrefix("-"){
            var strKey = argument;
            strKey = String(argument[argument.index(argument.startIndex, offsetBy: 1)..<argument.endIndex])
            strPreKey = strKey;
            continue;
        }
        
        let strValue = argument;
        if strPreKey != nil{
            let preValue = dicArg[strPreKey!];
            if (preValue == nil ){
                dicArg[strPreKey!] = strValue
            }
            else if preValue is NSMutableArray{
                let arr = preValue as! NSMutableArray;
                arr.add(strValue)
            }else if(strPreKey == "f"){
                let arr = NSMutableArray();
                if(preValue != nil){
                    arr.add(preValue as! String)
                }
                arr.add(strValue)
                dicArg[strPreKey!] = arr
            }
        }
    }
    
    
    
    
    let cmd = CommandLine.arguments[1];
    var strSecKey = dicArg["s"] as! String?
    if strPreKey == nil{
        strSecKey = dicArg["secKey"] as! String?
    }
    if strPreKey == nil{
        strSecKey = dicArg["prikey"] as! String?
    }
    
    
    switch cmd {
    case "g":
        var keyphrase = dicArg["k"] as! String?
        
        if keyphrase != nil && strSecKey != nil {
            print("seckey [s] is specified,the key phrass [k] will be ignored");
        }
        else if(keyphrase != nil){
            var dataKeyPhrase =  keyphrase!.data(using: .utf8);
            
            // if length of keyphrase is less than 4 ,treat it as word count
            if dataKeyPhrase!.count < 4 {
                let c =  Int(keyphrase!);
                keyphrase =  WordList.genKeyPhrase(c!);
                dataKeyPhrase = keyphrase!.data(using: .utf8)
            }
            if dataKeyPhrase!.count < 10{
                print("key phrase is too short < 10")
                exit(1)
            }
            
            // Scrypt
            var kdfType = 1;
            let kt = dicArg["kt"] as! String?
            if(kt != nil && kt   == "2"){
                kdfType = 2;
            }
            
            let kp = try LTEccTool.shared.genKeyPair(nil, keyPhrase:keyphrase,kdftype: kdfType)
            
            if(kdfType == 1){
                let msg = """
            scrypt N = 16384 r = 8 p = 1
            salt [length \(KDF.scryptSalt.count)]:
            \u{001B}[31;49m\(KDF.scryptSalt)\u{001B}[0;0m
            
            phrase [length \(keyphrase!.count)]:\u{001B}[31;49m\(keyphrase!)\u{001B}[0;0m
            
            """
                print(msg);
            }else{
                print("Passphrase:(PBKDF2,sha256 ,salt:base64-Kj3rk8+cKYG8sAhXO5gkU5nRrBzuhhS7ts953vdhVHE= rounds:123456)");
                print("\u{001B}[31;49m\(keyphrase!) \u{001B}[0;0m")
            }
            
            
            let keyData = try  LTBase64.base64Decode(kp.priKey);
            printKey(key: keyData)
            
            let resultStr = """
prikey:\(kp.priKey)
pubKey:\(kp.pubKey)

unset EC_PUBKEY EC_SECKEY
export set EC_PUBKEY=\(kp.pubKey) EC_SECKEY=\(kp.priKey)
"""
            print(resultStr);
            
            
            if kp != nil && CommandLine.arguments.contains("-S"){
                
                print("\u{001B}[31;48m this action [-S] will overwite the key in keychain. continue[y/n] ? \u{001B}[0;0m")
                let s = readLine();
                if(s == "Y" || s == "y"){
                    LEccKeyChain.shared.saveKeyInKeychain(secureKey: kp.priKey, publicKey: kp.pubKey)
                }
            }
            
            
            
        }else {
            let kp = try LTEccTool.shared.genKeyPair(strSecKey, keyPhrase:nil )
            
            let keyData = try  LTBase64.base64Decode(kp.priKey);
            printKey(key: keyData)
            
            let resultStr = """
prikey:\(kp.priKey)
pubKey:\(kp.pubKey)

unset EC_PUBKEY EC_SECKEY
export set EC_PUBKEY=\(kp.pubKey) EC_SECKEY=\(kp.priKey)
"""
            print(resultStr)
            
            if kp != nil && CommandLine.arguments.contains("-S"){
                
                print("\u{001B}[31;48m this action [-S] will overwite the key in keychain. continue[y/n] ? \u{001B}[0;0m")
                let s = readLine();
                if(s == "Y" || s == "y"){
                    LEccKeyChain.shared.saveKeyInKeychain(secureKey: kp.priKey, publicKey: kp.pubKey)
                }
            }
        }
        
    case "e":
        var strPubKey = dicArg["p"] as!  String?
        if (strPubKey == nil  ) {
            strPubKey = dicArg["pubKey"] as!  String?
        }
        if (strPubKey == nil){
            strPubKey = LEccKeyChain.shared.getPublicKeyInKeychain();
        }
        
        if(strPubKey == nil){
            Lprint("need pubkey ,use -p pubkey");
            exit(1);
        }
        
        let files = dicArg["f"];
        if files != nil {
            let gz = dicArg["z"] as! String?
            let isGz = !(gz == "0");
            
            let t:CryptAlgorithm
            let atype = dicArg["a"] as! String?
            if(atype == "a"){
                t = CryptAlgorithm.aes256
            }else{
                t = CryptAlgorithm.salsa20
            }
            
            
            if files is Array<Any>{
                for file in files as! [String] {
                    try LTEccTool.shared.ecEncryptFile(filePath: file , outFilePath: nil , pubkeyString: strPubKey! ,gzip: isGz, alg:t);
                }
                
            }else if files is String{
                try LTEccTool.shared.ecEncryptFile(filePath: files as! String, outFilePath: nil , pubkeyString: strPubKey!,gzip: isGz,alg:t);
            }
            
            
            
            break
        }
        
        
        let strmsg = dicArg["m"] as! String?
        var dataMsg = strmsg?.data(using: .utf8);
        if(dataMsg == nil){
            dataMsg = readDataFromStdIn();
        }
        
        if dataMsg != nil {
            
            let t:CryptAlgorithm
            let atype = dicArg["a"] as! String?
            if(atype == "a"){
                t = CryptAlgorithm.aes256
            }else{
                t = CryptAlgorithm.salsa20
            }
            
            let z = (dicArg["z"] as! String? != "0") ? 1 : 0
            
            let d = try LTEccTool.shared .ecEncrypt(data: dataMsg!, pubKey: strPubKey!,zipfirst: z,type: t);
            
            _ = d.withUnsafeBytes({ bf  in
                fwrite(bf.baseAddress, 1, bf.count, stdout);
            })
        }
        
        
    case "d":
        var seckey = dicArg["s"] as!  String?
        if (seckey == nil  ) {
            seckey = dicArg["prikey"] as!  String?
        }
        if (seckey == nil){
            seckey = LEccKeyChain.shared.getPrivateKeyInKeychain();
        }
        
        if(seckey == nil){
            Lprint("need seckey ,use  -s seckey");
            exit(1);
        }
        
        let files = dicArg["f"];
        if files != nil {
            if files is Array<Any>{
                for file in files as! [String] {
                    do{
                        try LTEccTool.shared.ecDecryptFile(filePath: file, outFilePath: nil , prikeyString: seckey!)
                    }
                    catch let e {
                        redPrint(e)
//                        Lprint(e);
                    }
                    
                }
                
            }else if files is String{
                do{
                    try LTEccTool.shared.ecDecryptFile(filePath: files as! String, outFilePath: nil , prikeyString: seckey!)
                }catch let e {
                    Lprint(e)
                    redPrint(e)
                }
            }
            
            
            
            break
        }
        
        
        let strmsg = dicArg["m"] as! String?
        var dataMsg = strmsg?.data(using: .utf8);
        if(dataMsg == nil){
            dataMsg = readDataFromStdIn();
        }
        
        if dataMsg != nil {
            let d = try LTEccTool.shared .ecDecrypt(encData: dataMsg!, priKey: seckey!);
            
            _ = d.withUnsafeBytes({ bf  in
                fwrite(bf.baseAddress, 1, bf.count, stdout);
            })
        }
    case "s":
        let s = LEccKeyChain.shared.getPrivateKeyInKeychain();
        let g = LEccKeyChain.shared.getPublicKeyInKeychain();
        if s != nil && g != nil {
            
            let dataOfSecure = try LTBase64.base64Decode(s!);
            printKey(key: dataOfSecure)
            let msg =
"""
----
privateKey:\(s!)
publicKey:\(g!)
export set EC_PUBKEY=\(g!) EC_SECKEY=\(s!)
unset EC_PUBKEY EC_SECKEY
"""
            print(msg);
        }else{
            print("no key in keychain or read fail")
        }
    case "r":
        let strmsg = dicArg["m"] as! String?
        var dataMsg = strmsg?.data(using: .utf8);
        if(dataMsg == nil){
            dataMsg = readDataFromStdIn();
        }
        let s = RandomArt.randomArt(data: dataMsg!, title: nil , end: nil)
        print("\n\(s)");
        break
    default:
        Lprint(helpMsg)
    }
        
}while false
}
catch let e {
//    print(e)
    redPrint(e)
}

//let t = Test();
//t.test();
